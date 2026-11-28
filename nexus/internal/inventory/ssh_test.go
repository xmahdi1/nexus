package inventory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSSHAdapterUsesFixedAllowlistedCommandsAndPinnedLoopbackHost(t *testing.T) {
	service := fixture(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	encryption := bytes.Repeat([]byte{3}, 32)
	encrypted, err := nexuscrypto.Encrypt(encryption, pem.EncodeToMemory(private))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	configuration := &ssh.ServerConfig{NoClientAuth: true}
	configuration.AddHostKey(signer)
	commands := make(chan string, 20)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		server, channels, requests, err := ssh.NewServerConn(connection, configuration)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for request := range requests {
					if request.Type != "exec" {
						request.Reply(false, nil)
						continue
					}
					var payload struct{ Command string }
					if ssh.Unmarshal(request.Payload, &payload) != nil {
						return
					}
					commands <- payload.Command
					request.Reply(true, nil)
					switch {
					case strings.HasPrefix(payload.Command, "printf '%s\\n'"):
						fmt.Fprint(channel, "fixture-host\n6.fixture\n\"Fixture Linux\"\n")
					case payload.Command == "ss -H -lntu":
						fmt.Fprintln(channel, "tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*")
					case payload.Command == serviceCommand:
						fmt.Fprint(channel, "Id=ssh.service\nLoadState=loaded\nActiveState=active\nSubState=running\n")
					case payload.Command == addressCommand:
						fmt.Fprint(channel, `[{"ifname":"eth0","mtu":1500,"operstate":"UP","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"}]}]`)
					case payload.Command == routes4Command:
						fmt.Fprint(channel, `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]`)
					case payload.Command == routes6Command:
						fmt.Fprint(channel, `[{"dst":"default","gateway":"fe80::1","dev":"eth0"}]`)
					case payload.Command == blockDevicesCommand:
						fmt.Fprint(channel, `{"blockdevices":[{"kname":"vda1","size":10737418240,"type":"part","maj:min":"254:1","ro":false}]}`)
					case payload.Command == mountsCommand:
						fmt.Fprint(channel, `{"filesystems":[{"target":"/","fstype":"ext4","maj:min":"254:1"}]}`)
					case payload.Command == resolversCommand:
						fmt.Fprint(channel, "127.0.0.53\n2001:db8::53\n")
					case payload.Command == "command -v docker":
						fmt.Fprintln(channel, "/usr/bin/docker")
					case payload.Command == dockerContainers:
						fmt.Fprintln(channel, strings.Repeat("a", 64))
					case payload.Command == dockerInspect+strings.Repeat("a", 64):
						fmt.Fprintln(channel, `{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"/db","image":"db:1","state":"running","exposed":{"3306/tcp":{}},"published":{}}`)
					case payload.Command == dockerNetworks:
						fmt.Fprintln(channel, `{"id":"fixture123456","name":"testnet","driver":"bridge","scope":"local"}`)
					case payload.Command == dockerVolumes:
						fmt.Fprintln(channel, `{"name":"data","driver":"local","scope":"local"}`)
					case payload.Command == dockerImages:
						fmt.Fprintf(channel, "{\"id\":\"sha256:%s\",\"repository\":\"db\",\"tag\":\"1\",\"digest\":\"<none>\"}\n", strings.Repeat("b", 64))
					case payload.Command == nginxCommand || payload.Command == caddyCommand:
						input, err := io.ReadAll(io.LimitReader(channel, int64(len(proxyScanner)+1)))
						if err != nil || string(input) != proxyScanner {
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
							return
						}
						fmt.Fprintln(channel, `{"routes":[],"certificates":[],"complete":true,"tlsComplete":true}`)
					default:
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
						return
					}
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
			}()
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	if err := service.DB.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"host": host, "port": port, "private_key_enc": encrypted}).Error; err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	defer pool.Remove("dev")
	pool.SetHostKeyCallback(func(id, fingerprint string) error {
		if id != "dev" || fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			return fmt.Errorf("untrusted fixture")
		}
		return nil
	})
	adapter := &SSHAdapter{DB: service.DB, Key: encryption, Pool: pool}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	observation, err := adapter.Collect(ctx, "dev")
	if err != nil || !observation.HostOK || !observation.DockerOK || !observation.SocketsOK || !observation.ServicesOK || len(observation.Services) != 1 {
		t.Fatal("collector failed", observation, err)
	}
	if len(observation.Containers) != 1 || len(observation.Ports) != 2 ||
		!observation.AddressesOK || !observation.Routes4OK || !observation.Routes6OK ||
		len(observation.Interfaces) != 1 || len(observation.Addresses) != 1 || len(observation.Routes) != 2 ||
		observation.Routes[0].Gateway != "192.0.2.1" || observation.Routes[1].Gateway != "fe80::1" {
		t.Fatal("observations missing", observation)
	}
	if !observation.BlockDevicesOK || !observation.MountsOK || !observation.ResolversOK ||
		len(observation.BlockDevices) != 1 || len(observation.Mounts) != 1 || len(observation.Resolvers) != 2 {
		t.Fatal("storage or DNS observations missing", observation)
	}
	if !observation.DockerNetworksOK || !observation.DockerVolumesOK || !observation.DockerImagesOK {
		t.Fatal("Docker resource observations missing", observation)
	}
	if !observation.NginxOK || !observation.CaddyOK || !observation.NginxTLSOK || !observation.CaddyTLSOK {
		t.Fatal("proxy collectors did not confirm their empty snapshots")
	}
	for i := 0; i < 17; i++ {
		select {
		case command := <-commands:
			if strings.Contains(command, ".Config.Env") || strings.Contains(command, "sudo") || strings.Contains(command, " nmap ") {
				t.Fatal("unsafe collector command")
			}
		case <-ctx.Done():
			t.Fatal("missing fixed command")
		}
	}
}
