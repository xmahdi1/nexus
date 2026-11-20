package filemanager

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/testssh"
	"golang.org/x/crypto/ssh"
)

func TestSFTPVersionAndStalledOperationsRespectCancellation(t *testing.T) {
	for _, version := range []bool{false, true} {
		t.Run(map[bool]string{false: "version_handshake", true: "file_operation"}[version], func(t *testing.T) {
			client := testssh.Client(t, func(channel ssh.Channel, command string) uint32 {
				if command != "subsystem:sftp" {
					return 126
				}
				if version {
					// Receive INIT and negotiate SFTP v3, then deliberately stop responding.
					var length uint32
					if err := binary.Read(channel, binary.BigEndian, &length); err != nil || length > 1024 {
						return 1
					}
					if _, err := io.CopyN(io.Discard, channel, int64(length)); err != nil {
						return 1
					}
					if _, err := channel.Write([]byte{0, 0, 0, 5, 2, 0, 0, 0, 3}); err != nil {
						return 1
					}
				}
				io.Copy(io.Discard, channel)
				return 0
			})
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			remote, err := openSFTP(ctx, client)
			if version {
				if err != nil {
					t.Fatal("version negotiation failed", err)
				}
				defer remote.Close()
				if _, err := remote.Stat("/fixture-do-not-access"); err == nil {
					t.Fatal("stalled operation succeeded")
				}
			} else if err == nil {
				remote.Close()
				t.Fatal("stalled negotiation succeeded")
			}
			if time.Since(start) > time.Second {
				t.Fatal("SFTP cancellation did not bound waiting")
			}
		})
	}
}
