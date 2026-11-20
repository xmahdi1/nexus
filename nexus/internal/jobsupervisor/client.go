package jobsupervisor

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
)

//go:embed remote.py
var remote string

//go:embed worker.py
var worker []byte

var identityPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Snapshot struct {
	State        string `json:"state"`
	Verified     bool   `json:"verified"`
	Empty        bool   `json:"empty"`
	InvocationID string `json:"invocationID"`
	ExitCode     *int   `json:"exitCode"`
	Output       string `json:"output"`
	Truncated    bool   `json:"truncated"`
	Released     bool   `json:"released"`
	Detail       string `json:"detail"`
	NoDispatch   bool   `json:"noDispatch"`
}

func (s Snapshot) Terminal() bool {
	return s.Verified && s.Empty && (s.State == "exited" || s.State == "failed" || s.State == "cancelled" || s.State == "timed_out" || s.State == "interrupted")
}

type Request struct {
	BeforeDispatch func() bool `json:"-"`
	Action         string      `json:"action"`
	ID             string      `json:"id,omitempty"`
	Hash           string      `json:"hash,omitempty"`
	InvocationID   string      `json:"invocationID,omitempty"`
	Command        string      `json:"command,omitempty"`
	RuntimeSeconds int         `json:"runtimeSeconds,omitempty"`
	Worker         string      `json:"worker,omitempty"`
}

func Digest(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// Execute sends all command/output-bearing data over stdin. The shell command
// contains only the fixed protocol implementation, never user input.
func Execute(ctx context.Context, client *ssh.Client, request Request) (Snapshot, error) {
	var result Snapshot
	if request.Action != "probe" {
		if !identityPattern.MatchString(request.ID) || !hashPattern.MatchString(request.Hash) || (request.InvocationID != "" && !identityPattern.MatchString(request.InvocationID)) {
			return result, errors.New("invalid supervisor identity")
		}
	}
	switch request.Action {
	case "start":
		if len(request.Command) == 0 || len(request.Command) > 16384 || !utf8.ValidString(request.Command) || strings.ContainsRune(request.Command, 0) || Digest(request.Command) != request.Hash || request.RuntimeSeconds < 1 || request.RuntimeSeconds > 600 {
			return Snapshot{State: "not_started", NoDispatch: true, Detail: "invalid_command"}, errors.New("invalid supervised command")
		}
		request.Worker = base64.StdEncoding.EncodeToString(worker)
	case "probe", "inspect", "cancel", "release":
		request.Command = ""
		request.Worker = ""
	default:
		return result, errors.New("unsupported supervisor action")
	}
	if request.Action == "start" {
		platform, err := nexusssh.Run(ctx, client, "uname -s", nil, 5*time.Second)
		if err != nil {
			return Snapshot{State: "not_started", NoDispatch: true, Detail: "platform_preflight_failed"}, nil
		}
		if strings.TrimSpace(platform) != "Linux" {
			return Snapshot{State: "unsupported", NoDispatch: true, Detail: "requires_root_systemd_cgroup_v2_python3"}, nil
		}
		if request.BeforeDispatch != nil && !request.BeforeDispatch() {
			return Snapshot{State: "not_started", NoDispatch: true, Detail: "execution_authority_changed"}, nil
		}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	defer clear(payload)
	command := "/usr/bin/python3 -I -S -c '" + strings.ReplaceAll(remote, "'", `'"'"'`) + "'"
	output, err := nexusssh.Run(ctx, client, command, strings.NewReader(string(payload)), 25*time.Second)
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) && exit.ExitStatus() == 127 {
			return Snapshot{State: "unsupported", NoDispatch: request.Action == "start", Detail: "requires_root_systemd_cgroup_v2_python3"}, nil
		}
		return Snapshot{State: "unknown", Detail: "transport_or_protocol_failure"}, err
	}
	if len(output) > 100000 || json.Unmarshal([]byte(output), &result) != nil {
		return Snapshot{State: "unknown"}, errors.New("invalid supervisor response")
	}
	if result.InvocationID != "" && !identityPattern.MatchString(result.InvocationID) {
		return Snapshot{State: "unknown"}, errors.New("invalid supervisor invocation")
	}
	switch result.State {
	case "accepted", "supported", "unsupported", "capacity_exceeded", "unknown", "running", "exited", "failed", "cancelled", "timed_out", "interrupted":
	default:
		return Snapshot{State: "unknown"}, errors.New("invalid supervisor state")
	}
	if result.ExitCode != nil && (*result.ExitCode < 0 || *result.ExitCode > 255) {
		return Snapshot{State: "unknown"}, errors.New("invalid supervisor exit code")
	}
	if result.NoDispatch && (request.Action != "start" || (result.State != "unsupported" && result.State != "capacity_exceeded")) {
		return Snapshot{State: "unknown"}, errors.New("invalid no-dispatch receipt")
	}
	if result.Detail != "" {
		known := map[string]bool{"invalid_request": true, "requires_root_systemd_cgroup_v2_python3": true, "invalid_identity": true, "invalid_command": true, "invalid_runtime": true, "private_artifact_limit": true, "identity_already_reserved": true, "invalid_worker": true, "dispatch_acknowledgement_lost": true, "inspect_before_any_retry": true, "artifact_identity_mismatch": true, "stop_failed": true, "cgroup_not_empty": true, "receipt_identity_mismatch": true, "missing_terminal_receipt": true, "release_requires_verified_terminal_state": true, "unexpected_artifact": true, "inspection_or_dispatch_unavailable": true}
		if !known[result.Detail] {
			return Snapshot{State: "unknown", Detail: "invalid_protocol_detail"}, errors.New("invalid supervisor detail")
		}
	}
	if result.Verified && request.Action != "probe" && result.InvocationID == "" {
		return Snapshot{State: "unknown"}, errors.New("missing supervisor invocation")
	}
	if result.Verified && (result.State == "exited" || result.State == "failed") && (!result.Empty || result.ExitCode == nil) {
		return Snapshot{State: "unknown"}, errors.New("incomplete terminal receipt")
	}
	data, err := base64.StdEncoding.DecodeString(result.Output)
	if err != nil || len(data) > 65536 {
		clear(data)
		return Snapshot{State: "unknown"}, errors.New("invalid supervisor output")
	}
	result.Output = string(data)
	clear(data)
	return result, nil
}
