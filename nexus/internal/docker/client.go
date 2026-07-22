package docker

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

const dockerPath = `PATH="$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin" docker`

type Client struct {
	ssh *ssh.Client
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
}

func NewClient(sshClient *ssh.Client) *Client {
	return &Client{ssh: sshClient}
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

func (c *Client) LogsStream(id string, tail int) (io.ReadCloser, error) {
	sess, err := c.ssh.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	pipe, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd := fmt.Sprintf(`%s logs --tail %d --timestamps --follow %s 2>&1`, dockerPath, tail, shellescape(id))
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	return &logStream{reader: pipe, session: sess}, nil
}

func (s *logStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *logStream) Close() error               { return s.session.Close() }

func (c *Client) exec(cmd string) (string, error) {
	sess, err := c.ssh.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	if err != nil {
		if strings.Contains(err.Error(), "127") {
			return "", fmt.Errorf("docker not found on this server")
		}
		return "", err
	}
	return string(out), nil
}

func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
