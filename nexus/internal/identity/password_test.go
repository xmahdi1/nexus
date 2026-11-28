package identity

import (
	"strings"
	"testing"
)

func TestArgonPasswordRoundTripAndSalt(t *testing.T) {
	password := []byte("fixture owner password")
	first, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("reused password salt")
	}
	if !VerifyPassword(first, password) || VerifyPassword(first, []byte("incorrect")) {
		t.Fatal("password verification failed")
	}
	if !strings.HasPrefix(first, "$argon2id$v=19$") {
		t.Fatal("new hash not Argon2id")
	}
	for _, password := range [][]byte{[]byte("short"), []byte(strings.Repeat("x", 1025))} {
		if _, err := HashPassword(password); err == nil {
			t.Fatal("invalid password length accepted")
		}
	}
}
func TestMalformedHashRejectedBeforeWork(t *testing.T) {
	for _, hash := range []string{
		"plaintext", "$2a$99$" + strings.Repeat("a", 53), "$2a$04$" + strings.Repeat("!", 53),
		"$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8192,t=999999999,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=8192,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8192,t=1,p=0$c2FsdA$aGFzaA",
	} {
		if ValidatePasswordHash(hash) == nil || VerifyPassword(hash, []byte("password")) {
			t.Fatal("malformed/expensive hash accepted")
		}
	}
}
