package ansible

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
)

type envelope struct {
	Salt    []byte          `json:"salt"`
	Payload json.RawMessage `json:"payload"`
}

// A random salt stays inside the ciphertext. Public approval digests cannot be
// used to guess low-entropy secrets in playbook content or variables. Rotation
// preserves the salt and immutable approval identity while rewrapping the data.
func (s *Service) seal(kind, id, server string, value any) (string, string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", "", err
	}
	defer clear(data)
	salt := make([]byte, 32)
	defer clear(salt)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	hash := sha256.New()
	hash.Write(salt)
	hash.Write(data)
	wrapped, err := json.Marshal(envelope{salt, data})
	if err != nil {
		return "", "", err
	}
	defer clear(wrapped)
	sealed, err := nexuscrypto.EncryptAnsiblePayload(s.Key, kind, id, server, wrapped)
	return sealed, hex.EncodeToString(hash.Sum(nil)), err
}
func (s *Service) open(kind, id, server, sealed, digest string, out any) error {
	data, err := nexuscrypto.DecryptAnsiblePayload(s.Key, kind, id, server, sealed)
	if err != nil {
		return errors.New("protected Ansible data unavailable")
	}
	defer clear(data)
	var wrapped envelope
	if json.Unmarshal(data, &wrapped) != nil || len(wrapped.Salt) != 32 {
		return ErrInput
	}
	defer clear(wrapped.Salt)
	defer clear(wrapped.Payload)
	hash := sha256.New()
	hash.Write(wrapped.Salt)
	hash.Write(wrapped.Payload)
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrConflict
	}
	return json.Unmarshal(wrapped.Payload, out)
}
