package crypto

import (
	"bytes"
	"testing"
)

func TestBackupCredentialsRequireMatchingPolicyServerAndKey(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	for _, server := range []string{"", "server-a"} {
		sealed, err := EncryptBackupPolicy(key, "policy-a", server, []byte("private fixture"))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := DecryptBackupPolicy(key, "policy-a", server, sealed)
		if err != nil || string(plain) != "private fixture" {
			t.Fatal("matching policy failed", err)
		}
		for _, binding := range [][2]string{{"policy-b", server}, {"policy-a", "server-b"}} {
			if _, err := DecryptBackupPolicy(key, binding[0], binding[1], sealed); err == nil {
				t.Fatal("backup credentials accepted a different context")
			}
		}
		if _, err := DecryptBackupPolicy(bytes.Repeat([]byte{8}, 32), "policy-a", server, sealed); err == nil {
			t.Fatal("wrong backup key accepted")
		}
	}
	if _, err := EncryptBackupPolicy(key[:16], "policy", "", nil); err == nil {
		t.Fatal("short backup key accepted")
	}
}

func TestRetentionRequestCannotMoveAcrossRunOrExecutionContext(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	binding := `["server","policy","actor","session","digest","target","backup:retention-apply"]`
	sealed, err := EncryptBackupRetention(key, "run", binding, []byte(`{"keepLast":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBackupRetention(key, "other-run", binding, sealed); err == nil {
		t.Fatal("retention request moved to another run")
	}
	if _, err := DecryptBackupRetention(key, "run", binding+"changed", sealed); err == nil {
		t.Fatal("retention request changed actor/target context")
	}
	if _, err := DecryptBackupPolicy(key, "run", binding, sealed); err == nil {
		t.Fatal("retention request accepted as a backup definition")
	}
}
