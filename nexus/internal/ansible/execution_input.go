package ansible

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/automation"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type privateTarget struct {
	ServerID   string `json:"serverId"`
	Alias      string `json:"alias"`
	Host       string `json:"host"`
	User       string `json:"user"`
	Port       int    `json:"port"`
	PrivateKey string `json:"privateKey"`
	KnownHosts string `json:"knownHosts"`
}

// freshTarget performs a new authenticated handshake against the existing pin.
// It never learns/persists a key on first use and never starts a target command.
func freshTarget(ctx context.Context, server models.Server, key []byte) (privateTarget, error) {
	result := privateTarget{ServerID: server.ID, Alias: automation.Alias("host", server.ID), Host: server.Host, Port: server.Port, User: server.Username}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return result, errors.New("target SSH credential unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	address := net.JoinHostPort(server.Host, fmt.Sprint(server.Port))
	raw, err := (&net.Dialer{}).DialContext(bounded, "tcp", address)
	if err != nil {
		return result, errors.New("target SSH handshake unavailable")
	}
	defer raw.Close()
	deadline, _ := bounded.Deadline()
	raw.SetDeadline(deadline)
	stop := context.AfterFunc(bounded, func() { raw.Close() })
	defer stop()
	connection, _, _, err := ssh.NewClientConn(raw, address, &ssh.ClientConfig{User: server.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, hostKey ssh.PublicKey) error {
		if ssh.FingerprintSHA256(hostKey) != server.KnownHostKey {
			return errors.New("target host key changed")
		}
		result.KnownHosts = knownhosts.Line([]string{address}, hostKey) + "\n"
		return nil
	}})
	if err != nil {
		return privateTarget{}, errors.New("target SSH identity could not be verified")
	}
	connection.Close()
	if bounded.Err() != nil || result.KnownHosts == "" {
		return privateTarget{}, errors.New("target SSH verification interrupted")
	}
	result.PrivateKey = string(key)
	return result, nil
}

func (runtime *Runtime) vaultValue(ctx context.Context, reference VaultReference, token, binding string) (string, error) {
	if token == "" || runtime.Pool == nil {
		return "", errors.New("supply a short-lived token for every referenced Vault server")
	}
	var profile vault.Profile
	var server models.Server
	if runtime.DB.First(&profile, "server_id=?", reference.ServerID).Error != nil || runtime.DB.First(&server, "id=?", reference.ServerID).Error != nil {
		return "", ErrConflict
	}
	current, err := vaultBinding(profile, server)
	if err != nil || current != binding {
		return "", ErrConflict
	}
	key, err := nexuscrypto.Decrypt(runtime.Key, server.PrivateKeyEnc)
	if err != nil {
		return "", ErrDenied
	}
	defer clear(key)
	transport, err := runtime.Pool.GetContext(ctx, nexusssh.ServerConfig{ID: server.ID, Host: server.Host, Port: server.Port, User: server.Username, PrivKey: key})
	if err != nil {
		return "", errors.New("Vault SSH transport unavailable")
	}
	client, err := vault.NewClient(profile, transport.DialContext)
	if err != nil {
		return "", ErrInput
	}
	defer client.CloseIdleConnections()
	result, err := vault.KV(ctx, client, profile, "read", vault.KVRequest{Token: token, Mount: reference.Mount, Path: reference.Path, Version: &reference.Version}, nil)
	if err != nil {
		return "", errors.New("approved Vault secret version unavailable")
	}
	defer clear(result.Data)
	var object map[string]json.RawMessage
	var value string
	if json.Unmarshal(result.Data, &object) != nil || json.Unmarshal(object[reference.Field], &value) != nil || !safeText(value, 4096) {
		return "", errors.New("Vault reference must select a bounded literal string")
	}
	return value, nil
}

func (runtime *Runtime) privateInput(ctx context.Context, plan Plan, identity string, tokens map[string]string) ([]byte, error) {
	check := func() error {
		run, err := runtime.Get(plan.ServerID, identity)
		if err != nil || run.OperationContext != plan.ID || run.CancelRequestedAt != nil || run.FinishedAt != nil || run.DispatchStartedAt != nil || !runtime.Allowed(run) || ctx.Err() != nil {
			return ErrDenied
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	cfg, err := runtime.config(plan)
	if err != nil {
		return nil, err
	}
	_, bundle, err := runtime.revision(plan.ServerID, plan.ProjectID, plan.RevisionID)
	if err != nil {
		return nil, err
	}
	var controller models.Server
	if err := runtime.DB.First(&controller, "id=?", plan.ServerID).Error; err != nil {
		return nil, err
	}
	frozen, err := target(controller)
	if err != nil || frozen.Fingerprint != cfg.Controller.Fingerprint {
		return nil, ErrConflict
	}
	controllerKey, err := nexuscrypto.Decrypt(runtime.Key, controller.PrivateKeyEnc)
	if err != nil {
		return nil, ErrDenied
	}
	defer clear(controllerKey)
	controllerSigner, err := ssh.ParsePrivateKey(controllerKey)
	if err != nil {
		return nil, errors.New("controller SSH credential unavailable")
	}
	input := struct {
		ID            string          `json:"id"`
		Bundle        Bundle          `json:"bundle"`
		Options       Options         `json:"options"`
		Variables     map[string]any  `json:"variables"`
		Targets       []privateTarget `json:"targets"`
		VaultPassword *string         `json:"vaultPassword,omitempty"`
	}{ID: identity, Bundle: bundle, Options: cfg.Options, Variables: map[string]any{}, Targets: []privateTarget{}}
	for _, wanted := range cfg.Targets {
		if err := check(); err != nil {
			return nil, err
		}
		var server models.Server
		if err := runtime.DB.First(&server, "id=?", wanted.ServerID).Error; err != nil {
			return nil, err
		}
		frozen, err := target(server)
		if err != nil || frozen.Fingerprint != wanted.Fingerprint {
			return nil, ErrConflict
		}
		key, err := nexuscrypto.Decrypt(runtime.Key, server.PrivateKeyEnc)
		if err != nil {
			return nil, ErrDenied
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil || string(signer.PublicKey().Marshal()) == string(controllerSigner.PublicKey().Marshal()) {
			clear(key)
			return nil, errors.New("targets need SSH credentials distinct from the controller credential")
		}
		resolved, err := freshTarget(ctx, server, key)
		clear(key)
		if err != nil {
			return nil, err
		}
		input.Targets = append(input.Targets, resolved)
	}
	for name, value := range cfg.Variables {
		if _, object := value.(map[string]any); object {
			ref, err := validateReference(value)
			if err != nil {
				return nil, err
			}
			if err := check(); err != nil {
				return nil, err
			}
			value, err = runtime.vaultValue(ctx, ref, tokens[ref.ServerID], cfg.VaultBindings[ref.ServerID])
			if err != nil {
				return nil, err
			}
		}
		input.Variables[name] = value
	}
	if cfg.Options.VaultPassword != nil {
		ref := *cfg.Options.VaultPassword
		if err := check(); err != nil {
			return nil, err
		}
		value, err := runtime.vaultValue(ctx, ref, tokens[ref.ServerID], cfg.VaultBindings[ref.ServerID])
		if err != nil || value == "" || strings.Contains(value, "\n") {
			return nil, errors.New("approved Ansible Vault password unavailable")
		}
		input.VaultPassword = &value
	}
	if err := check(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > jobsupervisor.MaxPrivateInput {
		clear(data)
		return nil, errors.New("approved execution input exceeds the private transport limit")
	}
	return data, nil
}
