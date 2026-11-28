package crypto

import (
	"bytes"
	"testing"
)

func TestJobOutputPurposeAndIdentityBinding(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	value := []byte("protected output fixture")
	sealed, err := EncryptJobOutput(key, "run", "server", value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecryptJobOutput(key, "run", "server", sealed)
	if err != nil || !bytes.Equal(decoded, value) {
		t.Fatal(err)
	}
	for _, test := range []struct {
		id, server string
		key        []byte
	}{{"other", "server", key}, {"run", "other", key}, {"run", "server", bytes.Repeat([]byte{5}, 32)}} {
		if _, err := DecryptJobOutput(test.key, test.id, test.server, sealed); err == nil {
			t.Fatal("binding or key accepted")
		}
	}
	if _, err := DecryptDeploymentVariables(key, "run", "server", sealed); err == nil {
		t.Fatal("job output accepted as deployment variables")
	}
	altered := sealed[:len(sealed)-4] + "AAAA"
	if _, err := DecryptJobOutput(key, "run", "server", altered); err == nil {
		t.Fatal("tampered output accepted")
	}
}
