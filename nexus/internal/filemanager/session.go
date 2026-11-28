package filemanager

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/pkg/sftp"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
)

const transferTimeout = 2 * time.Minute
const maxTransferBytes int64 = 64 << 20

type fileSession struct {
	*sftp.Client
	closeSession func()
	once         sync.Once
	closeErr     error
}

func (c *fileSession) Close() error {
	c.once.Do(func() { c.closeSession(); c.closeErr = c.Client.Close() })
	return c.closeErr
}

// openSFTP bounds both the SSH subsystem handshake and SFTP version negotiation.
// The parent deadline/cancellation also closes blocked transfer/stat operations.
func openSFTP(parent context.Context, client *ssh.Client) (*fileSession, error) {
	setup, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	session, err := nexusssh.OpenSession(setup, client)
	if err != nil {
		return nil, err
	}
	stopSetup := context.AfterFunc(setup, func() { session.Close() })
	fail := func(err error) (*fileSession, error) { stopSetup(); session.Close(); return nil, err }
	reader, err := session.StdoutPipe()
	if err != nil {
		return fail(err)
	}
	writer, err := session.StdinPipe()
	if err != nil {
		return fail(err)
	}
	if err := nexusssh.SessionRequest(setup, session, func() error { return session.RequestSubsystem("sftp") }); err != nil {
		return fail(err)
	}
	remote, err := sftp.NewClientPipe(io.LimitReader(reader, 96<<20), writer)
	if err != nil {
		return fail(err)
	}
	if err := setup.Err(); err != nil {
		remote.Close()
		return fail(err)
	}
	stopSetup()
	stop := context.AfterFunc(parent, func() { session.Close() })
	return &fileSession{Client: remote, closeSession: func() { stop(); session.Close() }}, nil
}
