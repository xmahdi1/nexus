package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	passwordMemory      = 64 * 1024 // KiB
	passwordIterations  = 3
	passwordParallelism = 2
)

// HashPassword creates a salted Argon2id PHC string. Plaintext is never persisted.
func HashPassword(password []byte) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("password must contain 12 to 1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(password, salt, passwordIterations, passwordMemory, passwordParallelism, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", passwordMemory, passwordIterations, passwordParallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

type argonHash struct {
	memory, iterations uint32
	parallelism        uint8
	salt, digest       []byte
}

// Parsing rejects unbounded parameters before allocating memory or hashing.
func parseArgon(encoded string) (argonHash, error) {
	var parsed argonHash
	invalid := errors.New("invalid or unsupported password hash")
	parts := strings.Split(encoded, "$")
	if len(encoded) > 512 || len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return parsed, invalid
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return parsed, invalid
	}
	memoryText, memoryOK := strings.CutPrefix(params[0], "m=")
	iterationsText, iterationsOK := strings.CutPrefix(params[1], "t=")
	parallelismText, parallelismOK := strings.CutPrefix(params[2], "p=")
	if !memoryOK || !iterationsOK || !parallelismOK {
		return parsed, invalid
	}
	memory, err := strconv.ParseUint(memoryText, 10, 32)
	if err != nil || memory < 8192 || memory > 128*1024 {
		return parsed, invalid
	}
	iterations, err := strconv.ParseUint(iterationsText, 10, 32)
	if err != nil || iterations < 1 || iterations > 5 {
		return parsed, invalid
	}
	parallelism, err := strconv.ParseUint(parallelismText, 10, 8)
	if err != nil || parallelism < 1 || parallelism > 4 {
		return parsed, invalid
	}
	parsed.salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(parsed.salt) != 16 {
		return parsed, invalid
	}
	parsed.digest, err = base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(parsed.digest) != 32 {
		return parsed, invalid
	}
	parsed.memory = uint32(memory)
	parsed.iterations = uint32(iterations)
	parsed.parallelism = uint8(parallelism)
	return parsed, nil
}

// ValidatePasswordHash accepts supported legacy bcrypt without rehashing it.
func ValidatePasswordHash(encoded string) error {
	if strings.HasPrefix(encoded, "$argon2id$") {
		_, err := parseArgon(encoded)
		return err
	}
	if len(encoded) == 60 && (strings.HasPrefix(encoded, "$2a$") || strings.HasPrefix(encoded, "$2b$") || strings.HasPrefix(encoded, "$2y$")) {
		cost, err := bcrypt.Cost([]byte(encoded))
		if err == nil && cost >= bcrypt.MinCost && cost <= 16 {
			const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
			for _, c := range encoded[7:] {
				if !strings.ContainsRune(alphabet, c) {
					return errors.New("invalid bcrypt encoding")
				}
			}
			return nil
		}
	}
	return errors.New("invalid or unsupported password hash")
}

// VerifyPassword supports the saved bcrypt hash and new Argon2id accounts.
// HTTP login still uses the legacy auth package until the session cutover.
func VerifyPassword(encoded string, password []byte) bool {
	if len(password) > 1024 || ValidatePasswordHash(encoded) != nil {
		return false
	}
	if strings.HasPrefix(encoded, "$argon2id$") {
		parsed, err := parseArgon(encoded)
		if err != nil {
			return false
		}
		candidate := argon2.IDKey(password, parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, 32)
		return subtle.ConstantTimeCompare(candidate, parsed.digest) == 1
	}
	return bcrypt.CompareHashAndPassword([]byte(encoded), password) == nil
}
