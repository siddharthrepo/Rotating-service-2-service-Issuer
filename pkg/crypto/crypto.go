// Package crypto holds the two hashing decisions this system makes.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/argon2"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

func DefaultArgon2Params() structs.Argon2Params {
	return structs.Argon2Params{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func HashSecret(plaintext string, p structs.Argon2Params) (string, error) {
	p = withParamDefaults(p)

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	key := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifySecret re-derives using the parameters stored in the hash itself.
func VerifySecret(plaintext, encoded string) (bool, error) {
	h, err := parseArgon2Hash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(plaintext), h.salt, h.iterations, h.memory, h.parallelism, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func GenerateToken() (plaintext, hash string, err error) {
	raw, err := randomB64(constants.TokenEntropyBytes)
	if err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	plaintext = constants.TokenPrefix + raw
	return plaintext, HashToken(plaintext), nil
}

func GenerateClientSecret() (string, error) {
	raw, err := randomB64(constants.TokenEntropyBytes)
	if err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}
	return constants.ClientSecretPrefix + raw, nil
}

func NewID() string { return ulid.Make().String() }
