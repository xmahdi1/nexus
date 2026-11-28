package ansibleenv

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewedBundleMatchesPublicSources(t *testing.T) {
	packed, err := base64.StdEncoding.DecodeString(bundle)
	if err != nil {
		t.Fatal(err)
	}
	r, err := zlib.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var files map[string][]byte
	if err := json.Unmarshal(data, &files); err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatal("unexpected bundle files")
	}
	for _, name := range []string{"environment.py", "requirements.lock"} {
		current, err := os.ReadFile(filepath.Join("../../../integrations/ansible", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(current, files[name]) {
			t.Fatal("regenerate reviewed bundle after source changes", name)
		}
	}
	for _, action := range []string{"install", "update", "health", "remove"} {
		cmd, err := Command(action)
		if err != nil || len(cmd) > 16384 || !strings.HasPrefix(cmd, "exec /usr/bin/python3 -I -c ") {
			t.Fatal("unbounded environment command", action, err)
		}
	}
	if _, err := Command("install; reboot"); err == nil {
		t.Fatal("caller command accepted")
	}
}
