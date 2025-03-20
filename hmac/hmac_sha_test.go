package hmac

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/dipper/types"
)

func TestAlgorithm(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.HmacSha256},
		{algorithm: types.HmacSha512},
	}

	for _, tc := range tcs {
		ki := new(ShaKeyImportImpl)

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		assert.Equal(t, tc.algorithm, key.Algorithm(), "Algorithm failed")
	}
}

func TestExport(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.HmacSha256},
		{algorithm: types.HmacSha512},
	}

	for _, tc := range tcs {
		ki := new(ShaKeyImportImpl)

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		password, err := key.Export()
		assert.NoErrorf(t, err, "Export failed: %s", err)
		assert.Equal(t, []byte("123456"), password, "Export failed")
	}
}

func TestSKI(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.HmacSha256},
		{algorithm: types.HmacSha512},
	}

	for _, tc := range tcs {
		ki := new(ShaKeyImportImpl)

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		expectedSKI := sha256.Sum256([]byte("123456"))
		assert.Equal(t, expectedSKI[:], key.SKI(), "SKI failed")
	}
}

func TestUnsupportedMethod(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.HmacSha256},
		{algorithm: types.HmacSha512},
	}

	for _, tc := range tcs {
		ki := new(ShaKeyImportImpl)

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		_, err = key.PublicKey()
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "PublicKey failed")

		_, err = key.Encrypt([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Encrypt failed")

		_, err = key.Decrypt([]byte("hello world"))
		assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Decrypt failed")
	}
}

func TestHmacShaSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{algorithm: types.HmacSha256},
		{algorithm: types.HmacSha512},
	}

	for _, tc := range tcs {
		ki := new(ShaKeyImportImpl)

		k, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		msg := []byte("hello world")
		signature, err := k.Sign(msg)
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		t.Log(string(signature))

		valid, err := k.Verify(msg, signature)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, valid, "Verify failed")
	}
}
