package pbkdf2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/go-crypto-suite/types"
)

func TestSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm  types.Algorithm
		saltSize   int
		iterations int
	}{
		{
			algorithm: types.Pbkdf2Sha256,
		},
		{
			algorithm: types.Pbkdf2Sha512,
		},
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
		ki := new(KeyGeneratorImpl[string])

		k, err := ki.KeyGen(tc.algorithm, WithIterations[string](tc.iterations), WithSaltSize[string](tc.saltSize))
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		signature, err := k.Sign("123456")
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		t.Log(signature)

		result, err := k.Verify("123456", signature)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, result, "Verify failed")

	}
}
