package crypto

import (
	"bytes"
	"testing"
)

func TestDeploymentCiphertextIsRandomAuthenticatedAndIdentityBound(t *testing.T) {
	key := bytes.Repeat([]byte{8}, 32)
	secret := []byte(`{"password":"private-fixture"}`)
	one, err := EncryptDeploymentVariables(key, "app-one", "host-one", secret)
	if err != nil {
		t.Fatal(err)
	}
	two, err := EncryptDeploymentVariables(key, "app-one", "host-one", secret)
	if err != nil || one == two {
		t.Fatal("nonce reuse", err)
	}
	cleartext, err := DecryptDeploymentVariables(key, "app-one", "host-one", one)
	if err != nil || !bytes.Equal(cleartext, secret) {
		t.Fatal("roundtrip", err)
	}
	for _, tc := range []struct {
		key              []byte
		id, host, cipher string
	}{
		{key, "app-two", "host-one", one}, {key, "app-one", "host-two", one}, {bytes.Repeat([]byte{9}, 32), "app-one", "host-one", one}, {key, "app-one", "host-one", one[:len(one)-2] + "AA"},
	} {
		if _, err := DecryptDeploymentVariables(tc.key, tc.id, tc.host, tc.cipher); err == nil {
			t.Fatal("wrong binding/key or tampering accepted")
		}
	}
}
