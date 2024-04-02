package ecdsa

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/go-crypto-suite/types"
)

func TestSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.EcdsaP256,
		},
		{
			algorithm: types.EcdsaP384,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl[string])

		privKey, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		ct, err := privKey.Sign("hello world")
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		t.Log(ct)

		plaintext, err := pubKey.Verify("hello world", ct)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, plaintext, "Verify failed")
	}
}

func TestKeyImport(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.EcdsaP256,
		},
		{
			algorithm: types.EcdsaP384,
		},
		{
			algorithm: types.EcdsaP521,
		},
	}

	for _, tc := range tcs {
		kg := new(KeyGeneratorImpl[string])

		privKey, err := kg.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		privKeyStr, err := privKey.Bytes()
		assert.NoErrorf(t, err, "Bytes failed: %s", err)

		ki := new(KeyImportImpl[string])

		privKey, err = ki.KeyImport(privKeyStr, tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		pubKeyStr, err := pubKey.Bytes()
		assert.NoErrorf(t, err, "Bytes failed: %s", err)

		pubKey, err = ki.KeyImport(pubKeyStr, tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)
	}
}
