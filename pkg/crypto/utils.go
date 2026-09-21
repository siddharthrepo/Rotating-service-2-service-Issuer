package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

// ErrInvalidHash means a stored hash is not a hash this code can read.
var ErrInvalidHash = errors.New("malformed argon2 hash")

type argon2Hash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func parseArgon2Hash(encoded string) (*argon2Hash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidHash, version)
	}

	var h argon2Hash
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.iterations, &h.parallelism); err != nil {
		return nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, ErrInvalidHash
	}
	h.salt, h.key = salt, key
	return &h, nil
}

func withParamDefaults(p structs.Argon2Params) structs.Argon2Params {
	d := DefaultArgon2Params()
	if p.MemoryKiB == 0 {
		p.MemoryKiB = d.MemoryKiB
	}
	if p.Iterations == 0 {
		p.Iterations = d.Iterations
	}
	if p.Parallelism == 0 {
		p.Parallelism = d.Parallelism
	}
	if p.SaltLength == 0 {
		p.SaltLength = d.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = d.KeyLength
	}
	return p
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
