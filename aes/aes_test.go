package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/go-crypto-suite/types"
)

func TestEncryptAndDecrypt(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.AesCbc128,
		},
		{
			algorithm: types.AesCbc192,
		},
		{
			algorithm: types.AesCbc256,
		},
		{
			algorithm: types.AesGcm128,
		},
		{
			algorithm: types.AesGcm192,
		},
		{
			algorithm: types.AesGcm256,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyImportImpl[string])

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		ct, err := key.Encrypt("hello world")
		assert.NoErrorf(t, err, "Encrypt failed: %s", err)

		t.Log(ct)

		plaintext, err := key.Decrypt(ct)
		assert.NoErrorf(t, err, "Decrypt failed: %s", err)
		assert.Equal(t, "hello world", plaintext, "Decrypt failed")
	}
}
