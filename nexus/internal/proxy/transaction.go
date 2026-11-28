package proxy

import (
	"fmt"
	"regexp"
	"strings"
)

// configurationTransaction backs up owned files/symlinks, validates the edited
// configuration and restores the previous files on failure. A lost SSH result
// still requires inspection; this cannot prove the remote process stopped.
func configurationTransaction(paths []string, change, validate, reload, lockPath, backupPattern string) string {
	var backup, restore strings.Builder
	for i, p := range paths {
		quoted := shellQuote(p)
		fmt.Fprintf(&backup, "if [ -d %s ]; then echo 'managed config path is a directory'; rm -rf -- \"$backup\"; exit 1; fi\n", quoted)
		fmt.Fprintf(&backup, "if [ -e %s ] || [ -L %s ]; then cp -a -- %s \"$backup/%d\" || { rm -rf -- \"$backup\"; exit 1; }; fi\n", quoted, quoted, quoted, i)
		fmt.Fprintf(&restore, "if ! rm -f -- %s; then restored=0; fi\nif [ -e \"$backup/%d\" ] || [ -L \"$backup/%d\" ]; then if ! cp -a -- \"$backup/%d\" %s; then restored=0; fi; fi\n", quoted, i, i, i, quoted)
	}
	return `umask 077
export PATH="$PATH:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
command -v flock >/dev/null 2>&1 || { echo 'flock is required for safe proxy configuration'; exit 1; }
` + "[ ! -L " + shellQuote(lockPath) + " ] || exit 1\nexec 9>" + shellQuote(lockPath) + ` || exit 1
flock -n 9 || { echo 'proxy configuration is busy'; exit 1; }
backup=$(mktemp -d ` + shellQuote(backupPattern) + `) || exit 1
` + backup.String() + `
changed=0
committed=0
reload_attempted=0
finish() {
 status=$?
 trap - EXIT HUP INT TERM
 if [ "$changed" = 1 ] && [ "$committed" != 1 ]; then
  restored=1
` + restore.String() + `
  if [ "$restored" = 1 ] && [ "$reload_attempted" = 1 ]; then
   if ! { ` + validate + `; } || ! { ` + reload + `; }; then restored=0; fi
  fi
  if [ "$restored" != 1 ]; then printf 'proxy recovery failed; private backup retained: %s\n' "$backup"; exit 73; fi
 fi
 if ! rm -rf -- "$backup"; then echo 'proxy backup cleanup failed'; exit 74; fi
 exit "$status"
}
trap finish EXIT
trap 'exit 130' HUP INT TERM
changed=1
` + change + `
if ! { ` + validate + `; }; then exit 1; fi
reload_attempted=1
if ! { ` + reload + `; }; then exit 1; fi
committed=1
`
}

func proxyTransaction(run func(string) (string, error), paths []string, change, validate, reload string) error {
	out, err := run(configurationTransaction(paths, change, validate, reload, "/run/nexus-proxy.lock", "/tmp/nexus-proxy-recovery.XXXXXXXXXX"))
	if err != nil {
		if retained := regexp.MustCompile(`/tmp/nexus-proxy-recovery\.[A-Za-z0-9]{10}`).FindString(out); retained != "" {
			return fmt.Errorf("private recovery backup retained at %s: %w", retained, err)
		}
	}
	return err
}
