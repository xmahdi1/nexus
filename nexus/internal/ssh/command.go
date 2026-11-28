package ssh

import (
	"bytes"
	"context"
	"errors"
	"github.com/xmahdi1/nexus/internal/audit"
	"io"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const CommandOutputLimit = 1 << 20
const CommandTimeout = 2 * time.Minute

var ErrOutputLimit = errors.New("remote command output exceeded limit")
var ErrRemoteUnknown = errors.New("remote outcome is uncertain; inspect target state before retrying")

// Run bounds session opening, execution and combined output. Closing a channel
// does not prove that remote child processes stopped; timed-out mutations must
// be inspected before retrying. A stalled channel open closes the transport.
func Run(parent context.Context, client *gossh.Client, command string, input io.Reader, timeout time.Duration) (out string, resultErr error) {
	var attempted atomic.Bool
	defer func() {
		var exit *gossh.ExitError
		if attempted.Load() && resultErr != nil && !errors.As(resultErr, &exit) {
			audit.MarkRemoteUnknown(parent)
			resultErr = errors.Join(ErrRemoteUnknown, resultErr)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	session, err := OpenSession(ctx, client)
	if err != nil {
		return "", err
	}
	defer session.Close()
	output := &commandOutput{limit: CommandOutputLimit, cancel: cancel}
	session.Stdout, session.Stderr, session.Stdin = output, output, input
	done := make(chan error, 1)
	go func() {
		if err := ctx.Err(); err != nil {
			done <- err
			return
		}
		attempted.Store(true)
		done <- session.Run(command)
	}()
	select {
	case err := <-done:
		text, exceeded := output.result()
		if exceeded {
			return text, ErrOutputLimit
		}
		if ctx.Err() != nil {
			return text, ctx.Err()
		}
		return text, err
	case <-ctx.Done():
		// Do not wait for a signal acknowledgement from an unresponsive peer.
		session.Close()
		text, exceeded := output.result()
		if exceeded {
			return text, ErrOutputLimit
		}
		return text, ctx.Err()
	}
}

type commandOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *commandOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.exceeded = true
		b.cancel()
	}
	b.buffer.Write(p)
	return n, nil
}
func (b *commandOutput) result() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String(), b.exceeded
}

// OpenSession bounds a channel-open handshake. SSH does not expose cancellation
// for this handshake, so a stalled peer requires closing the shared transport.
func OpenSession(ctx context.Context, client *gossh.Client) (*gossh.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type opened struct {
		session *gossh.Session
		err     error
	}
	ready := make(chan opened, 1)
	go func() { s, err := client.NewSession(); ready <- opened{s, err} }()
	var session *gossh.Session
	select {
	case result := <-ready:
		if result.err != nil {
			return nil, result.err
		}
		session = result.session
	case <-ctx.Done():
		client.Close()
		result := <-ready
		if result.session != nil {
			result.session.Close()
		}
		return nil, ctx.Err()
	}
	return session, nil
}

// SessionRequest bounds a PTY, shell or exec handshake on an existing channel.
func SessionRequest(ctx context.Context, session *gossh.Session, request func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- request() }()
	select {
	case err := <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		session.Close()
		return ctx.Err()
	}
}
