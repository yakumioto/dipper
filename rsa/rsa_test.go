package rsa

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
			algorithm: types.Rsa1024,
		},
		{
			algorithm: types.Rsa2048,
		},
		{
			algorithm: types.Rsa4096,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl[string])

		privKey, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		ct, err := pubKey.Encrypt("hello world")
		assert.NoErrorf(t, err, "Encrypt failed: %s", err)

		t.Log(ct)

		plaintext, err := privKey.Decrypt(ct)
		assert.NoErrorf(t, err, "Decrypt failed: %s", err)
		assert.Equal(t, "hello world", plaintext, "Decrypt failed")
	}
}

func TestSignAdnVerify(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.Rsa1024,
		},
		{
			algorithm: types.Rsa2048,
		},
		{
			algorithm: types.Rsa4096,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl[string])

		privKey, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		signature, err := privKey.Sign("hello world")
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		t.Log(signature)

		ok, err := pubKey.Verify("hello world", signature)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, ok, "Verify failed")
	}
}

func TestKeyImport(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.Rsa1024,
		},
		{
			algorithm: types.Rsa2048,
		},
		{
			algorithm: types.Rsa4096,
		},
	}

	for _, tc := range tcs {
		kg := new(KeyGeneratorImpl[string])

		privKey, err := kg.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		privKeyStr, err := privKey.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)

		ki := new(KeyImportImpl[string])

		privKey, err = ki.KeyImport(privKeyStr, tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		pubKeyStr, err := pubKey.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)

		pubKey, err = ki.KeyImport(pubKeyStr, tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)
	}
}
