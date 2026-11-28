package docker

import (
	"context"
	"encoding/json"
	"fmt"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const dockerPath = `PATH="$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin" docker`

type Client struct {
	ssh *ssh.Client
	ctx context.Context
}

type Container struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	State  string `json:"state"`
	Status string `json:"status"`
	Ports  string `json:"ports"`
}

type dockerPS struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	State  string `json:"State"`
	Status string `json:"Status"`
	Ports  string `json:"Ports"`
}

type logStream struct {
	reader  io.Reader
	session *ssh.Session
	stop    func() bool
}

func NewClient(sshClient *ssh.Client) *Client {
	return NewClientContext(context.Background(), sshClient)
}

func NewClientContext(ctx context.Context, client *ssh.Client) *Client {
	return &Client{ssh: client, ctx: ctx}
}

func (c *Client) List() ([]Container, error) {
	out, err := c.exec(dockerPath + ` ps -a --format '{{json .}}'`)
	if err != nil {
		return nil, err
	}
	var result []Container
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ps dockerPS
		if err := json.Unmarshal([]byte(line), &ps); err != nil {
			continue
		}
		result = append(result, Container{
			ID:     ps.ID,
			Name:   strings.TrimPrefix(ps.Names, "/"),
			Image:  ps.Image,
			State:  ps.State,
			Status: ps.Status,
			Ports:  ps.Ports,
		})
	}
	if result == nil {
		result = []Container{}
	}
	return result, nil
}

func (c *Client) Start(id string) error {
	_, err := c.exec(dockerPath + " start " + shellescape(id))
	return err
}
func (c *Client) Stop(id string) error {
	_, err := c.exec(dockerPath + " stop " + shellescape(id))
	return err
}
func (c *Client) Restart(id string) error {
	_, err := c.exec(dockerPath + " restart " + shellescape(id))
	return err
}
func (c *Client) Remove(id string) error {
	_, err := c.exec(dockerPath + " rm -f " + shellescape(id))
	return err
}

var containerLogTarget = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)

func (c *Client) LogsStream(id string, tail int) (io.ReadCloser, error) {
	if !containerLogTarget.MatchString(id) {
		return nil, fmt.Errorf("invalid container name or ID")
	}
	setup, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	sess, err := nexusssh.OpenSession(setup, c.ssh)
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	pipe, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	sess.Stdin = strings.NewReader(id + "\n")
	cmd := fmt.Sprintf(`IFS= read -r target && %s logs --tail %d --timestamps --follow -- "$target" 2>&1`, dockerPath, tail)
	if err := nexusssh.SessionRequest(setup, sess, func() error { return sess.Start(cmd) }); err != nil {
		sess.Close()
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	stop := context.AfterFunc(c.ctx, func() { sess.Close() })
	return &logStream{reader: pipe, session: sess, stop: stop}, nil
}

func (s *logStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *logStream) Close() error               { s.stop(); return s.session.Close() }

func (c *Client) exec(cmd string) (string, error) {
	out, err := nexusssh.Run(c.ctx, c.ssh, cmd, nil, nexusssh.CommandTimeout)
	return out, err
}

func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
