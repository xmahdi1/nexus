package compose

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const dockerPath = `PATH="$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin" docker`

func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func ReadFile(client *ssh.Client, path string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	out, err := sess.Output("cat " + shellescape(path))
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	return string(out), nil
}

func WriteFile(client *ssh.Client, path, content string) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	cmd := fmt.Sprintf("echo %s | base64 -d > %s", shellescape(encoded), shellescape(path))
	if err := sess.Run(cmd); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func Up(client *ssh.Client, path string) (string, error) {
	return execInDir(client, path, dockerPath+" compose up -d 2>&1")
}

func Down(client *ssh.Client, path string) (string, error) {
	return execInDir(client, path, dockerPath+" compose down 2>&1")
}

func execInDir(client *ssh.Client, filePath, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	out, err := sess.Output(fmt.Sprintf("cd %s && %s", shellescape(filepath.Dir(filePath)), cmd))
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output != "" {
			return output, fmt.Errorf("%s", output)
		}
		return "", err
	}
	return output, nil
}
