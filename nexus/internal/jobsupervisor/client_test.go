package jobsupervisor

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/testssh"
	"golang.org/x/crypto/ssh"
)

func TestCommandUsesOnlyStdinAndMissingInterpreterIsNotDispatch(t *testing.T) {
	for _, action := range []string{"start", "inspect"} {
		t.Run(action, func(t *testing.T) {
			command := "printf private-command-fixture"
			client := testssh.Client(t, func(channel ssh.Channel, script string) uint32 {
				if script == "uname -s" {
					io.WriteString(channel, "Linux\n")
					return 0
				}
				if strings.Contains(script, command) {
					t.Error("command payload appeared in SSH argv")
				}
				input, err := io.ReadAll(channel)
				if err != nil {
					t.Error(err)
					return 1
				}
				var request Request
				if err := json.Unmarshal(input, &request); err != nil {
					t.Error(err)
				}
				if action == "start" && (request.Command != command || request.Worker == "") {
					t.Error("stdin payload missing")
				}
				if action == "inspect" && (request.Command != "" || request.Worker != "") {
					t.Error("inspection transported execution payload")
				}
				return 127
			})
			result, err := Execute(context.Background(), client, Request{Action: action, ID: strings.Repeat("a", 32), Hash: Digest(command), Command: command, RuntimeSeconds: 1})
			if err != nil || result.State != "unsupported" || result.NoDispatch != (action == "start") {
				t.Fatal("missing interpreter status misclassified", result, err)
			}
		})
	}
}

func TestProtocolDetailsCannotExposeOutputThroughMetadata(t *testing.T) {
	client := testssh.Client(t, func(channel ssh.Channel, _ string) uint32 {
		io.Copy(io.Discard, channel)
		io.WriteString(channel, `{"state":"unknown","detail":"private output reflected into metadata"}`)
		return 0
	})
	result, err := Execute(context.Background(), client, Request{Action: "inspect", ID: strings.Repeat("a", 32), Hash: Digest("fixture")})
	if err == nil || strings.Contains(result.Detail, "private output") {
		t.Fatal("unstructured metadata accepted", result, err)
	}
}

func TestUnsupportedPlatformDoesNotReceiveCommandPayload(t *testing.T) {
	for _, platform := range []string{"FreeBSD", "Darwin"} {
		t.Run(platform, func(t *testing.T) {
			calls := 0
			client := testssh.Client(t, func(channel ssh.Channel, script string) uint32 {
				calls++
				if script != "uname -s" {
					t.Error("execution protocol sent to unsupported host")
				}
				io.WriteString(channel, platform+"\n")
				return 0
			})
			command := "private unsupported fixture"
			result, err := Execute(context.Background(), client, Request{Action: "start", ID: strings.Repeat("a", 32), Hash: Digest(command), Command: command, RuntimeSeconds: 1})
			if err != nil || !result.NoDispatch || result.State != "unsupported" || calls != 1 {
				t.Fatal("unsupported platform dispatch", result, err, calls)
			}
		})
	}
}

func TestInvalidLocalCommandIsKnownNotDispatched(t *testing.T) {
	for _, command := range []string{"invalid\xffcommand", "invalid\x00command"} {
		result, err := Execute(context.Background(), nil, Request{Action: "start", ID: strings.Repeat("a", 32), Hash: Digest(command), Command: command, RuntimeSeconds: 1})
		if err == nil || !result.NoDispatch || result.State != "not_started" {
			t.Fatal("invalid input became an uncertain remote outcome", result, err)
		}
	}
}
