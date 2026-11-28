package jobsupervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/testssh"
	"golang.org/x/crypto/ssh"
)

func TestDisposableSystemdSupervisor(t *testing.T) {
	address := os.Getenv("NEXUS_SUPERVISION_SSH")
	if address == "" {
		t.Skip("run scripts/supervision_lab.py")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" || len(os.Getenv("NEXUS_SUPERVISION_NONCE")) != 32 {
		t.Fatal("disposable loopback guest required")
	}
	key, err := os.ReadFile(os.Getenv("NEXUS_SUPERVISION_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("NEXUS_SUPERVISION_HOST_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	connect := func() *ssh.Client {
		t.Helper()
		client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(pinned), Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		marker, err := nexusssh.Run(context.Background(), client, "cat /nexus-fixture-nonce", nil, 5*time.Second)
		if err != nil || strings.TrimSpace(marker) != os.Getenv("NEXUS_SUPERVISION_NONCE") {
			client.Close()
			t.Fatal("guest identity mismatch", err)
		}
		return client
	}
	client := connect()
	defer func() { client.Close() }()
	probe, err := Execute(context.Background(), client, Request{Action: "probe"})
	if err != nil || probe.State != "supported" {
		t.Fatal("guest supervisor unavailable", probe, err)
	}
	for _, scenario := range []struct {
		name, command, expected string
		runtime                 int
		input                   []byte
		isolation               string
	}{
		{"completion", "printf supervised-output", "exited", 30, nil, ""},
		{"stdin-is-eof", "if read value; then exit 9; fi; printf eof-ok", "exited", 30, nil, ""},
		{"private-stdin", "python3 -c 'import sys; data=sys.stdin.buffer.read(); assert len(data)==98304 and data==b\"x\"*98304; print(\"private-input-ok\")'", "exited", 30, bytes.Repeat([]byte{'x'}, MaxPrivateInput), ""},
		{"detached-descendant-completes", "setsid sh -c 'sleep 1' </dev/null >/dev/null 2>&1 & exit 0", "exited", 30, nil, ""},
		{"failed-command", "exit 17", "failed", 30, nil, ""},
		{"disconnect-and-cancel", "trap '' TERM; sleep 300 & setsid sh -c 'trap \"\" TERM; printf detached-ready; sleep 300' & wait", "cancelled", 60, nil, ""},
		{"runtime-limit", "trap '' TERM; sleep 300 & wait", "timed_out", 2, nil, ""},
		{"worker-crash", "kill -KILL \"$PPID\"; sleep 300", "interrupted", 30, nil, ""},
		{"bounded-output", "python3 -c 'print(\"x\"*100000)'", "exited", 30, nil, ""},
		{"runner-isolation", `python3 -c 'import os; from pathlib import Path; assert os.path.ismount("/run/nexus-runner"); Path("/run/nexus-runner/fixture-private").write_text("private-runtime"); assert "NoNewPrivs:\t1" in Path("/proc/self/status").read_text(); print("runner-isolation-ok")'`, "exited", 720, nil, "github-runner"},
		{"runner-account-cleanup", `python3 -c 'import os,pwd,json,subprocess;from pathlib import Path;i=os.environ["NEXUS_JOB_ID"];name="nxr-"+i[:20];subprocess.run(["/usr/sbin/useradd","--system","--user-group","--home-dir","/run/nexus-runner/home","--shell","/usr/sbin/nologin",name],check=True);p=Path("/run/nexus-jobs")/i/"runner-account.json";p.write_text(json.dumps({"name":name,"uid":pwd.getpwnam(name).pw_uid}));p.chmod(0o600);print("account-created")'`, "exited", 30, nil, "github-runner"},
		{"runner-isolation-cancel", `python3 -c 'import subprocess;from pathlib import Path;Path("/run/nexus-runner/cancel-private").write_text("fixture");child=subprocess.Popen(["sleep","300"]);print("detached-ready",flush=True);child.wait()'`, "cancelled", 60, nil, "github-runner"},
		{"ansible-isolation", `python3 -c 'import os;from pathlib import Path;assert os.path.ismount("/run/nexus-ansible-job");assert "NoNewPrivs:\t1" in Path("/proc/self/status").read_text();Path("/run/nexus-ansible-job/fixture-private").write_text("private-runtime");print("ansible-isolation-ok")'`, "exited", 30, nil, "ansible"},
		{"ansible-account-cleanup", `python3 -c 'import os,pwd,json,subprocess;from pathlib import Path;i=os.environ["NEXUS_JOB_ID"];name="nxa-"+i[:20];subprocess.run(["/usr/sbin/useradd","--system","--user-group","--home-dir","/run/nexus-ansible-job/home","--shell","/usr/sbin/nologin",name],check=True);p=Path("/run/nexus-jobs")/i/"ansible-account.json";p.write_text(json.dumps({"name":name,"uid":pwd.getpwnam(name).pw_uid}));p.chmod(0o600);print("account-created")'`, "exited", 30, nil, "ansible"},
		{"ansible-isolation-cancel", `python3 -c 'import subprocess;child=subprocess.Popen(["sleep","300"]);print("detached-ready",flush=True);child.wait()'`, "cancelled", 60, nil, "ansible"},
		{"backup-isolation", `python3 -c 'import sys;from pathlib import Path;assert "NoNewPrivs:\t1" in Path("/proc/self/status").read_text();assert sys.stdin.read()=="backup-private-fixture";group=Path("/sys/fs/cgroup")/Path("/proc/self/cgroup").read_text().strip().split("::",1)[1].lstrip("/");assert int((group/"memory.max").read_text())==2147483648;print("backup-isolation-ok")'`, "exited", 86400, []byte("backup-private-fixture"), "backup"},
		{"backup-isolation-cancel", `python3 -c 'import subprocess;child=subprocess.Popen(["sleep","300"]);print("detached-ready",flush=True);child.wait()'`, "cancelled", 60, nil, "backup"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			random := make([]byte, 16)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			id := hex.EncodeToString(random)
			digest := DigestWithInput(scenario.command, scenario.input)
			result, err := Execute(context.Background(), client, Request{Action: "start", ID: id, Hash: digest, Command: scenario.command, Input: scenario.input, RuntimeSeconds: scenario.runtime, Isolation: scenario.isolation})
			if err != nil || result.State != "accepted" {
				t.Fatal("start failed", result, err)
			}
			invocation := ""
			if scenario.name == "disconnect-and-cancel" || strings.HasSuffix(scenario.name, "isolation-cancel") {
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					result, err = Execute(context.Background(), client, Request{Action: "inspect", ID: id, Hash: digest})
					if err != nil {
						t.Fatal(err)
					}
					if result.Verified && result.State == "running" && strings.Contains(result.Output, "detached-ready") {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if !strings.Contains(result.Output, "detached-ready") || result.Empty {
					t.Fatal("detached child did not start", result)
				}
				invocation = result.InvocationID
				client.Close()
				client = connect()
				observed, err := Execute(context.Background(), client, Request{Action: "inspect", ID: id, Hash: digest, InvocationID: invocation})
				if err != nil || observed.State != "running" || observed.Empty {
					t.Fatal("run did not survive reconnect", observed, err)
				}
				spoofed, err := Execute(context.Background(), client, Request{Action: "cancel", ID: id, Hash: digest, InvocationID: strings.Repeat("0", 32)})
				if err != nil || spoofed.Verified || spoofed.State != "unknown" {
					t.Fatal("mismatched invocation was allowed to cancel", spoofed, err)
				}
			}
			action := "inspect"
			if scenario.expected == "cancelled" {
				action = "cancel"
			}
			deadline := time.Now().Add(25 * time.Second)
			for time.Now().Before(deadline) {
				result, err = Execute(context.Background(), client, Request{Action: action, ID: id, Hash: digest, InvocationID: invocation})
				if err != nil {
					t.Fatal("inspection failed", err)
				}
				if result.InvocationID != "" {
					invocation = result.InvocationID
				}
				if result.Terminal() {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if !result.Terminal() || result.State != scenario.expected {
				t.Fatal("wrong terminal result", result, err)
			}
			if scenario.name == "runner-isolation" {
				if result.Output != "runner-isolation-ok\n" {
					t.Fatal("sandbox missing", result.Output)
				}
				if _, err := nexusssh.Run(context.Background(), client, "test ! -e /run/nexus-runner/fixture-private", nil, 5*time.Second); err != nil {
					t.Fatal("private runner filesystem leaked to host namespace")
				}
			}
			if scenario.name == "ansible-isolation" {
				if result.Output != "ansible-isolation-ok\n" {
					t.Fatal("Ansible sandbox missing", result.Output)
				}
				if _, err := nexusssh.Run(context.Background(), client, "test ! -e /run/nexus-ansible-job/fixture-private", nil, 5*time.Second); err != nil {
					t.Fatal("private Ansible filesystem leaked to host namespace")
				}
			}
			if scenario.name == "completion" && result.Output != "supervised-output" {
				t.Fatal("output lost", result)
			}
			if scenario.name == "private-stdin" && result.Output != "private-input-ok\n" {
				t.Fatal("private stdin leaked or was lost")
			}
			if scenario.name == "bounded-output" && (len(result.Output) != 65536 || !result.Truncated) {
				t.Fatal("output unbounded or truncation hidden", len(result.Output), result.Truncated)
			}
			if scenario.name == "failed-command" && (result.ExitCode == nil || *result.ExitCode != 17) {
				t.Fatal("exit code lost", result)
			}
			result, err = Execute(context.Background(), client, Request{Action: "release", ID: id, Hash: digest, InvocationID: invocation})
			if err != nil || !result.Released {
				t.Fatal("private artifacts not released", result, err)
			}
			if strings.HasSuffix(scenario.name, "account-cleanup") {
				prefix := "nxr-"
				if scenario.isolation == "ansible" {
					prefix = "nxa-"
				}
				if _, err := nexusssh.Run(context.Background(), client, "! id -u "+prefix+id[:20]+" >/dev/null 2>&1", nil, 5*time.Second); err != nil {
					t.Fatal("reserved job account retained after release")
				}
			}
		})
	}
	t.Run("lost-dispatch-acknowledgement-is-not-replayed", func(t *testing.T) {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			t.Fatal(err)
		}
		id := hex.EncodeToString(random)
		command := "printf x >> /tmp/nexus-fixture-" + id + "; sleep 30"
		digest := Digest(command)
		dispatched := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		bridge := testssh.Client(t, func(channel ssh.Channel, script string) uint32 {
			if script == "uname -s" {
				output, err := nexusssh.Run(context.Background(), client, script, nil, 5*time.Second)
				if err != nil {
					return 1
				}
				io.WriteString(channel, output)
				return 0
			}
			payload, err := io.ReadAll(io.LimitReader(channel, 200001))
			if err != nil {
				return 1
			}
			_, err = nexusssh.Run(context.Background(), client, script, bytes.NewReader(payload), 30*time.Second)
			clear(payload)
			close(dispatched)
			<-release
			if err != nil {
				return 1
			}
			return 0
		})
		done := make(chan error, 1)
		go func() {
			_, err := Execute(context.Background(), bridge, Request{Action: "start", ID: id, Hash: digest, Command: command, RuntimeSeconds: 60})
			done <- err
		}()
		select {
		case <-dispatched:
		case <-time.After(15 * time.Second):
			t.Fatal("guest dispatch did not complete")
		}
		bridge.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("lost acknowledgement reported success")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("lost acknowledgement stayed blocked")
		}
		result, err := Execute(context.Background(), client, Request{Action: "inspect", ID: id, Hash: digest})
		if err != nil || !result.Verified || result.State != "running" {
			t.Fatal("original run not inspectable", result, err)
		}
		repeated, err := Execute(context.Background(), client, Request{Action: "start", ID: id, Hash: digest, Command: command, RuntimeSeconds: 60})
		if err != nil || repeated.State != "unknown" || repeated.Detail != "identity_already_reserved" {
			t.Fatal("duplicate dispatch not refused", repeated, err)
		}
		// Fill the private artifact namespace in this pinned disposable guest.
		// Capacity must never turn an existing run into a no-dispatch result.
		fill := "python3 -c 'from pathlib import Path; b=Path(\"/run/nexus-jobs\"); [(b/(\"fixture-capacity-" + id + "-\"+str(i))).mkdir(mode=0o700) for i in range(1023)]'"
		cleanup := "python3 -c 'from pathlib import Path; b=Path(\"/run/nexus-jobs\"); [p.rmdir() for p in b.glob(\"fixture-capacity-" + id + "-*\")]'"
		t.Cleanup(func() {
			if _, err := nexusssh.Run(context.Background(), client, cleanup, nil, 10*time.Second); err != nil {
				t.Error("capacity fixture cleanup failed", err)
			}
		})
		if _, err := nexusssh.Run(context.Background(), client, fill, nil, 10*time.Second); err != nil {
			t.Fatal("capacity fixture setup failed", err)
		}
		repeated, err = Execute(context.Background(), client, Request{Action: "start", ID: id, Hash: digest, Command: command, RuntimeSeconds: 60})
		if err != nil || repeated.State != "unknown" || repeated.NoDispatch {
			t.Fatal("capacity erased an existing dispatch", repeated, err)
		}
		newID := strings.Repeat("f", 32)
		full, err := Execute(context.Background(), client, Request{Action: "start", ID: newID, Hash: digest, Command: command, RuntimeSeconds: 60})
		if err != nil || full.State != "capacity_exceeded" || !full.NoDispatch {
			t.Fatal("capacity did not reject a fresh dispatch", full, err)
		}
		count, err := nexusssh.Run(context.Background(), client, "cat /tmp/nexus-fixture-"+id, nil, 5*time.Second)
		if err != nil || count != "x" {
			t.Fatal("command replayed", count, err)
		}
		result, err = Execute(context.Background(), client, Request{Action: "cancel", ID: id, Hash: digest, InvocationID: result.InvocationID})
		if err != nil || !result.Terminal() {
			t.Fatal("could not stop recovered run", result, err)
		}
		result, err = Execute(context.Background(), client, Request{Action: "release", ID: id, Hash: digest, InvocationID: result.InvocationID})
		if err != nil || !result.Released {
			t.Fatal("could not release recovered run", result, err)
		}
	})
}
