package password_test

import (
	"testing"

	"github.com/bounoable/password"
	"github.com/stretchr/testify/assert"
)

func TestNewArgonParams(t *testing.T) {
	assert := assert.New(t)
	params := password.NewArgonParams()

	assert.Equal(uint32(64*1024), params.Memory)
	assert.Equal(uint8(2), params.Threads)
	assert.Equal(uint32(3), params.Iterations)
	assert.Equal(uint32(16), params.SaltLength)
	assert.Equal(uint32(32), params.KeyLength)
}

func TestNewArgonHasher(t *testing.T) {
	assert := assert.New(t)
	h := password.NewArgonHasher(password.NewArgonParams())

	assert.IsType(&password.ArgonHasher{}, h)
}

func TestHash(t *testing.T) {
	assert := assert.New(t)
	hasher := password.NewArgonHasher(password.NewArgonParams())
	password := "supersecret123"
	hashed, err := hasher.Hash(password)

	if err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(hashed, password)
	assert.NotEqual("", hashed)
}

func TestValidate(t *testing.T) {
	hasher := password.NewArgonHasher(password.NewArgonParams())
	password := "supersecret123"

	hashed, _ := hasher.Hash(password)

	valid, err := hasher.Validate(password, hashed)

	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Error("password validation failed")
	}
}

func TestValidateParams(t *testing.T) {
	params := password.NewArgonParams()
	params.Threads = 1
	params.Iterations = 5
	params.SaltLength = 24
	params.KeyLength = 64

	hasher := password.ArgonHasher{
		ArgonParams: params,
	}

	password := "supersecret123"
	hashed, _ := hasher.Hash(password)

	valid, err := hasher.Validate(password, hashed)

	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Error("password validation failed")
	}
}
