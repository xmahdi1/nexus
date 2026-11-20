package compose

import (
	"context"
	"crypto/sha256"
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

func ReadFile(ctx context.Context, client *ssh.Client, path string) (string, error) {
	return nexusssh.Run(ctx, client, "cat -- "+shellescape(path), nil, nexusssh.CommandTimeout)
}

func WriteFile(ctx context.Context, client *ssh.Client, path, content string) error {
	if len(content) > nexusssh.CommandOutputLimit {
		return fmt.Errorf("compose file exceeds 1 MiB")
	}
	// Transport recipe contents over stdin rather than placing secrets in argv.
	_, err := nexusssh.Run(ctx, client, writeCommand(path, content), strings.NewReader(content), nexusssh.CommandTimeout)
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

func writeCommand(path, content string) string {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	// Verify completeness before atomically replacing a recipe. A disconnected
	// stdin must not publish a truncated file or overwrite the previous recipe.
	return "umask 077; target=" + shellescape(path) + `; tmp=$(mktemp -- "${target}.nexus.XXXXXXXX") || exit 1; trap 'rm -f -- "$tmp"' EXIT HUP INT TERM; cat > "$tmp" && actual=$(sha256sum -- "$tmp") && [ "${actual%% *}" = ` + shellescape(digest) + ` ] && chmod 600 -- "$tmp" && mv -f -- "$tmp" "$target"`
}
