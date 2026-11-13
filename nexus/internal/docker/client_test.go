package docker

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A disposable loopback SSH server returns canned Docker output. It never
// invokes a shell, Docker daemon, or commands on a managed machine.
func TestListWithFakeSSH(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	commands := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			ch, reqs, err := channel.Accept()
			if err != nil {
				return
			}
			for req := range reqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				ssh.Unmarshal(req.Payload, &payload)
				commands <- payload.Command
				req.Reply(true, nil)
				fmt.Fprintln(ch, `{"ID":"abc123","Names":"/fixture-db","Image":"postgres:17","State":"running","Status":"Up","Ports":"5432/tcp"}`)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				ch.Close()
				break
			}
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "fixture", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	containers, err := NewClient(client).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != 1 || containers[0].Name != "fixture-db" || containers[0].Ports != "5432/tcp" {
		t.Fatalf("unexpected containers: %#v", containers)
	}
	if command := <-commands; !strings.Contains(command, "ps -a --format") {
		t.Fatalf("unexpected command %s", command)
	}
}
