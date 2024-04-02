package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/go-crypto-suite/types"
)

func TestHmacShaSignAndVerify(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.HmacSha256,
		},
		{
			algorithm: types.HmacSha512,
		},
	}

	for _, tc := range tcs {
		ki := new(ShaKeyImportImpl[string])

		k, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		ct, err := k.Sign("hello world")
		assert.NoErrorf(t, err, "Sign failed: %s", err)

		t.Log(ct)

		plaintext, err := k.Verify("hello world", ct)
		assert.NoErrorf(t, err, "Verify failed: %s", err)
		assert.True(t, plaintext, "Verify failed")
	}
}
