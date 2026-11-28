package compose

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
)

const dockerPath = `PATH="$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin" docker`

func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Frame the path on stdin, preserving quotes and trailing newlines.
const readPath = `IFS= read -r path64 || exit 1
target=$(printf '%s' "$path64" | base64 -d && printf '.') || exit 1
target=${target%.}
[ -n "$target" ] || exit 1
`

const readCommand = readPath + `exec cat -- "$target"`

const writeCommand = readPath + `IFS= read -r digest || exit 1
umask 077
tmp=$(mktemp -- "${target}.nexus.XXXXXXXX") || exit 1
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
cat > "$tmp" && actual=$(sha256sum < "$tmp") &&
  [ "${actual%% *}" = "$digest" ] && chmod 600 -- "$tmp" && mv -f -- "$tmp" "$target"`

func pathInput(path string) string {
	return base64.StdEncoding.EncodeToString([]byte(path)) + "\n"
}

func ReadFile(ctx context.Context, client *ssh.Client, path string) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("invalid YAML path")
	}
	return nexusssh.Run(ctx, client, readCommand, strings.NewReader(pathInput(path)), nexusssh.CommandTimeout)
}

func WriteFile(ctx context.Context, client *ssh.Client, path, content string) error {
	if len(content) > nexusssh.CommandOutputLimit {
		return fmt.Errorf("compose file exceeds 1 MiB")
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("invalid YAML path")
	}
	digest := sha256.Sum256([]byte(content))
	input := fmt.Sprintf("%s%x\n%s", pathInput(path), digest, content)
	_, err := nexusssh.Run(ctx, client, writeCommand, strings.NewReader(input), nexusssh.CommandTimeout)
	return err
}

func Up(ctx context.Context, client *ssh.Client, path string) (string, error) {
	return execInDir(ctx, client, path, "up -d")
}

func Down(ctx context.Context, client *ssh.Client, path string) (string, error) {
	return execInDir(ctx, client, path, "down")
}

func actionCommand(filePath, action string) string {
	return fmt.Sprintf("cd %s && %s compose -f %s %s 2>&1", shellescape(filepath.Dir(filePath)), dockerPath, shellescape(filepath.Base(filePath)), action)
}
func execInDir(ctx context.Context, client *ssh.Client, filePath, action string) (string, error) {
	out, err := nexusssh.Run(ctx, client, actionCommand(filePath, action), nil, nexusssh.CommandTimeout)
	return strings.TrimSpace(out), err
}
