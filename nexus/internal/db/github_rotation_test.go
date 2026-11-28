package db

import (
	"bytes"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
)

func TestGitHubRotationPreservesPurposeAndServerBindings(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{6}, 32), bytes.Repeat([]byte{9}, 32)
	for _, kind := range []string{"connection", "dispatch", "change", "webhook", "organization", "organization-change"} {
		sealed, err := nexuscrypto.EncryptGitHubPayload(oldKey, kind, "row", "build", []byte("private-fixture"))
		if err != nil {
			t.Fatal(err)
		}
		field := secretField{kind: "github-" + kind}
		next, err := rewrapSecret(field, oldKey, newKey, "row", "build", sealed)
		if err != nil {
			t.Fatal(err)
		}
		value, err := nexuscrypto.DecryptGitHubPayload(newKey, kind, "row", "build", next)
		if err != nil || string(value) != "private-fixture" {
			t.Fatal("rotation lost payload", err)
		}
		for _, context := range []struct{ kind, id, server string }{{kind, "copied", "build"}, {kind, "row", "other"}, {"invalid", "row", "build"}} {
			if _, err := nexuscrypto.DecryptGitHubPayload(newKey, context.kind, context.id, context.server, next); err == nil {
				t.Fatal("ciphertext context substitution accepted")
			}
		}
		if _, err := nexuscrypto.DecryptGitHubPayload(oldKey, kind, "row", "build", next); err == nil {
			t.Fatal("rotated payload accepted old key")
		}
	}
}
