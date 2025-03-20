package pbkdf2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/dipper/types"
)

func TestAlgorithm(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Pbkdf2Sha256},
		{algorithm: types.Pbkdf2Sha512},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		assert.Equal(t, tc.algorithm, key.Algorithm(), "Algorithm failed")
	}
}

func TestSKI(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Pbkdf2Sha256},
		{algorithm: types.Pbkdf2Sha512},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		assert.Nil(t, key.SKI(), "SKI failed")
	}
}

func TestUnsupportedMethod(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Pbkdf2Sha256},
		{algorithm: types.Pbkdf2Sha512},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		_, err = key.Export()
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Export failed")

		_, err = key.PublicKey()
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "PublicKey failed")

		_, err = key.Encrypt([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Encrypt failed")

		_, err = key.Decrypt([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Decrypt failed")
	}
}

func TestSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm  types.Algorithm
		saltSize   int
		iterations int
	}{
		{algorithm: types.Pbkdf2Sha256},
		{algorithm: types.Pbkdf2Sha512},
		{
			algorithm:  types.Pbkdf2Sha256,
			iterations: 20000,
		},
		{
			algorithm: types.Pbkdf2Sha256,
			saltSize:  64,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		k, err := ki.KeyGen(tc.algorithm, WithIterations(tc.iterations), WithSaltSize(tc.saltSize))
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		msg := []byte("123456")
		signature, err := k.Sign(msg)
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		t.Log(string(signature))

		result, err := k.Verify(msg, signature)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, result, "Verify failed")
	}
}
