package crypto

import (
	"bytes"
	"testing"
)

func TestAnsibleCiphertextRequiresExactPurposeRowControllerAndKey(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	sealed, err := EncryptAnsiblePayload(key, "revision", "revision-a", "controller-a", []byte("private fixture"))
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range [][3]string{{"plan", "revision-a", "controller-a"}, {"revision", "revision-b", "controller-a"}, {"revision", "revision-a", "controller-b"}} {
		if _, err := DecryptAnsiblePayload(key, binding[0], binding[1], binding[2], sealed); err == nil {
			t.Fatal("ciphertext context substitution admitted")
		}
	}
	if _, err := DecryptAnsiblePayload(bytes.Repeat([]byte{8}, 32), "revision", "revision-a", "controller-a", sealed); err == nil {
		t.Fatal("wrong key admitted")
	}
	if _, err := EncryptAnsiblePayload(key[:16], "revision", "revision-a", "controller-a", nil); err == nil {
		t.Fatal("non-master key accepted")
	}
	if _, err := EncryptAnsiblePayload(key, "arbitrary", "id", "server", nil); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}
