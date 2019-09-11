package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Errors
var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

// ArgonParams represent argon2 parameters.
type ArgonParams struct {
	Memory     uint32
	Threads    uint8
	Iterations uint32
	SaltLength uint32
	KeyLength  uint32
}

// Hasher represents a password hasher.
type Hasher interface {
	MustHash(s string) string
	Hash(s string) (string, error)
	Validate(plain string, encoded string) (bool, error)
}

// ArgonHasher hashes and validates passwords using the argon2id algorithm.
type ArgonHasher struct {
	ArgonParams ArgonParams
}

// NewArgonParams returns default argon2id parameters.
func NewArgonParams() ArgonParams {
	return ArgonParams{
		Memory:     64 * 1024,
		Threads:    2,
		Iterations: 3,
		SaltLength: 16,
		KeyLength:  32,
	}
}

// NewArgonHasher returns a new argon2id hasher.
func NewArgonHasher(params ArgonParams) *ArgonHasher {
	return &ArgonHasher{
		ArgonParams: params,
	}
}

func (h *ArgonHasher) MustHash(password string) string {
	hash, err := h.Hash(password)

	if err != nil {
		panic(err)
	}

	return hash
}

// Hash returns a hash of the password using the argon2id algorithm.
func (h *ArgonHasher) Hash(password string) (string, error) {
	params := h.ArgonParams

	salt, err := randomBytes(params.SaltLength)

	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Threads, params.KeyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, params.Memory, params.Iterations, params.Threads, b64Salt, b64Hash)

	return encoded, nil
}

func randomBytes(length uint32) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// Validate validates a plain-text password against an encoded password.
func (h *ArgonHasher) Validate(password, encoded string) (bool, error) {
	params, salt, hash, err := decodeHash(encoded)

	if err != nil {
		return false, err
	}

	passwordHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Threads, params.KeyLength)

	if subtle.ConstantTimeCompare(hash, passwordHash) == 0 {
		return false, nil
	}

	return true, nil
}

func decodeHash(encoded string) (params *ArgonParams, salt, hash []byte, err error) {
	vals := strings.Split(encoded, "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)

	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &ArgonParams{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Threads)

	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])

	if err != nil {
		return nil, nil, nil, err
	}

	params.SaltLength = uint32(len(salt))
	hash, err = base64.RawStdEncoding.DecodeString(vals[5])

	if err != nil {
		return nil, nil, nil, err
	}

	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
