package crypto

import (
	"bytes"
	"testing"
)

func TestCredentialRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plaintext := []byte("fixture-private-key-not-a-real-credential")
	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decrypt(key, encrypted)
	if err != nil || !bytes.Equal(restored, plaintext) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := Decrypt(bytes.Repeat([]byte{8}, 32), encrypted); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Decrypt(key, "invalid ciphertext"); err == nil {
		t.Fatal("invalid ciphertext accepted")
	}
}
