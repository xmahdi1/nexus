package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/testssh"
	gossh "golang.org/x/crypto/ssh"
)

func TestRunBoundsOutputCancellationAndRemoteFailures(t *testing.T) {
	client := testssh.Client(t, func(channel gossh.Channel, command string) uint32 {
		switch command {
		case "flood":
			io.WriteString(channel, strings.Repeat("x", CommandOutputLimit+100000))
			return 0
		case "wait":
			for {
				if _, err := io.WriteString(channel, "."); err != nil {
					return 0
				}
				time.Sleep(10 * time.Millisecond)
			}
		case "fail":
			fmt.Fprint(channel.Stderr(), "fixture failure")
			return 7
		case "input":
			io.Copy(channel, channel)
			return 0
		}
		return 1
	})
	out, err := Run(context.Background(), client, "flood", nil, time.Second)
	if !errors.Is(err, ErrOutputLimit) || len(out) != CommandOutputLimit {
		t.Fatalf("unbounded output: %d %v", len(out), err)
	}
	start := time.Now()
	if _, err := Run(context.Background(), client, "wait", nil, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("timeout not bounded: %v", err)
	}
	out, err = Run(context.Background(), client, "fail", nil, time.Second)
	var exit *gossh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 || out != "fixture failure" {
		t.Fatalf("failure hidden: %q %v", out, err)
	}
	out, err = Run(context.Background(), client, "input", strings.NewReader("private fixture input"), time.Second)
	if err != nil || out != "private fixture input" {
		t.Fatalf("stdin corrupted: %q %v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, client, "wait", nil, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Cancellation must also interrupt an already running session without closing
	// this shared transport; subsequent commands above/below still work.
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if _, err := Run(ctx, client, "wait", nil, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), client, "input", strings.NewReader("alive"), time.Second); err != nil {
		t.Fatal("shared transport lost", err)
	}
}

func TestCommandLostResultMarksUncertainButRemoteExitAndPreCancelDoNot(t *testing.T) {
	client := testssh.Client(t, func(channel gossh.Channel, command string) uint32 {
		if command == "exit" {
			return 7
		}
		for {
			if _, err := io.WriteString(channel, "."); err != nil {
				return 0
			}
			time.Sleep(time.Millisecond)
		}
	})
	ctx, result := audit.WithResult(context.Background())
	if _, err := Run(ctx, client, "wait", nil, 30*time.Millisecond); !errors.Is(err, ErrRemoteUnknown) || !result.RemoteUnknown() {
		t.Fatal("lost remote result was not marked uncertain", err)
	}
	ctx, result = audit.WithResult(context.Background())
	if _, err := Run(ctx, client, "exit", nil, time.Second); err == nil || errors.Is(err, ErrRemoteUnknown) || result.RemoteUnknown() {
		t.Fatal("explicit remote exit misclassified", err)
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, result = audit.WithResult(parent)
	if _, err := Run(ctx, client, "wait", nil, time.Second); !errors.Is(err, context.Canceled) || result.RemoteUnknown() {
		t.Fatal("pre-dispatch cancellation misclassified", err)
	}
}
