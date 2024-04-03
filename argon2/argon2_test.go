package argon2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/go-crypto-suite/types"
)

func TestSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
		method    string
		saltSize  int
		time      uint32
		memory    uint32
		threads   uint8
		length    uint32
	}{
		{
			algorithm: types.Argon2,
			method:    MethodArgon2id,
		},
		{
			algorithm: types.Argon2,
			method:    MethodArgon2i,
		},
		{
			algorithm: types.Argon2,
			method:    MethodArgon2i,
			saltSize:  32,
		},
		{
			algorithm: types.Argon2,
			method:    MethodArgon2i,
			time:      4,
		},
		{
			algorithm: types.Argon2,
			method:    MethodArgon2i,
			memory:    128 * 1024,
		},
		{
			algorithm: types.Argon2,
			method:    MethodArgon2i,
			threads:   8,
		},
		{
			algorithm: types.Argon2,
			method:    MethodArgon2i,
			length:    64,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl[string])

		k, err := ki.KeyGen(
			tc.algorithm,
			WithMethod[string](tc.method),
			WithSaltSize[string](tc.saltSize),
			WithTime[string](tc.time),
			WithMemory[string](tc.memory),
			WithThreads[string](tc.threads),
			WithLength[string](tc.length),
		)
		assert.NoError(t, err, "KeyGen failed")

		signature, err := k.Sign("123456")
		assert.NoError(t, err, "Sign failed")

		t.Log(signature)

		result, err := k.Verify("123456", signature)
		assert.NoError(t, err, "Verify failed")
		assert.True(t, result, "Verify failed")
	}
}
