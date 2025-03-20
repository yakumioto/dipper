package chacha20

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/dipper/types"
)

func TestAlgorithm(t *testing.T) {
	ki := new(KeyImportImpl)

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	assert.Equal(t, types.Chacha20, key.Algorithm(), "Algorithm failed")
}

func TestExport(t *testing.T) {
	ki := new(KeyImportImpl)

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	password, err := key.Export()
	assert.NoErrorf(t, err, "Export failed: %s", err)
	assert.Equal(t, []byte("123456"), password, "Export failed")
}

func TestSKI(t *testing.T) {
	ki := new(KeyImportImpl)

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	expectedSKI := sha256.Sum256([]byte("123456"))
	assert.Equal(t, expectedSKI[:], key.SKI(), "SKI failed")
}

func TestUnsupportedMethod(t *testing.T) {
	ki := new(KeyImportImpl)

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	_, err = key.PublicKey()
	assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "PublicKey failed")

	_, err = key.Sign([]byte("hello world"))
	assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Sign failed")

	_, err = key.Verify([]byte("hello world"), []byte("signature"))
	assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Verify failed")
}

func TestEncryptAndDecrypt(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.Chacha20,
		},
		{
			algorithm: types.XChacha20,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyImportImpl)

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		ct, err := key.Encrypt([]byte("hello world"))
		assert.NoErrorf(t, err, "Encrypt failed: %s", err)

		t.Log(string(ct))

		plaintext, err := key.Decrypt(ct)
		assert.NoErrorf(t, err, "Decrypt failed: %s", err)
		assert.Equal(t, []byte("hello world"), plaintext, "Decrypt failed")
	}
}
