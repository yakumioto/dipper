package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/dipper/types"
)

func TestAlgorithm(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)
		assert.Equal(t, tc.algorithm, key.Algorithm(), "Algorithm failed")

		pk, err := key.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)
		assert.Equal(t, tc.algorithm, pk.Algorithm(), "Algorithm failed")
	}
}

func TestExport(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		keyData, err := key.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)
		assert.NotEmpty(t, keyData, "Export failed")

		pk, err := key.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		pkData, err := pk.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)
		assert.NotEmpty(t, pkData, "Export failed")
	}
}

func TestSKI(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)
		assert.NotEmptyf(t, key.SKI(), "SKI failed")

		pk, err := key.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)
		assert.NotEmptyf(t, pk.SKI(), "SKI failed")
	}
}

func TestKeyPubicKey(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		privKey, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)
		assert.NotNil(t, pubKey, "PublicKey failed")

		_, err = pubKey.PublicKey()
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "PublicKey failed")
	}
}

func TestUnsupportedMethod(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		key, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		_, err = key.Encrypt([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Sign failed")

		_, err = key.Verify([]byte(""), []byte(""))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Verify failed")

		pk, err := key.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		_, err = pk.Decrypt([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Decrypt failed")

		_, err = pk.Sign([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Sign failed")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		privKey, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		msg := []byte("hello world")
		ct, err := pubKey.Encrypt(msg)
		assert.NoErrorf(t, err, "Encrypt failed: %s", err)

		t.Log(string(ct))

		plaintext, err := privKey.Decrypt(ct)
		assert.NoErrorf(t, err, "Decrypt failed: %s", err)
		assert.Equal(t, msg, plaintext, "Decrypt failed")
	}
}

func TestSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		ki := new(KeyGeneratorImpl)

		privKey, err := ki.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		msg := []byte("hello world")
		signature, err := privKey.Sign(msg)
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		t.Log(string(signature))

		ok, err := pubKey.Verify(msg, signature)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, ok, "Verify failed")
	}
}

func TestKeyImport(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.Rsa1024},
		{algorithm: types.Rsa2048},
		{algorithm: types.Rsa4096},
	}

	for _, tc := range tcs {
		kg := new(KeyGeneratorImpl)

		privKey, err := kg.KeyGen(tc.algorithm)
		assert.NoErrorf(t, err, "KeyGen failed: %s", err)

		privKeyData, err := privKey.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)

		ki := new(KeyImportImpl)

		privKey, err = ki.KeyImport(privKeyData, tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		pubKey, err := privKey.PublicKey()
		assert.NoErrorf(t, err, "PublicKey failed: %s", err)

		pubKeyData, err := pubKey.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)

		_, err = ki.KeyImport(pubKeyData, tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)
	}
}
