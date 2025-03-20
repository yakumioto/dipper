package dipper

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/dipper/types"
)

func TestKeyImport(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
		key       string
	}{
		{
			algorithm: types.HmacSha256,
			key:       "123456",
		},
		{
			algorithm: types.AesCbc128,
			key:       "123456",
		},
		{
			algorithm: types.EcdsaP256,
			key: `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwnWJemItHmVppEVm
D/Tc1lzhGJyUi0IjvIY6UlzM0nahRANCAARJnJkC+4xFfYsfYsbofxF0+bNCcPIU
M1AxZj5EQqfZ3wxDLr1a1rtFeTa5/i4PN75/1AB3MlPfqkN3mgMmi5EI
-----END EC PRIVATE KEY-----`,
		},
		{
			algorithm: types.Rsa1024,
			key: `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDLJOYAd+lAqdq4vZjTyg7E+PcKCScq67HskRXM3il97nqu/Vdj
qdZ+Cy/JZgXfqqitBhPUGD+zfa5is+7/5NH9eb+lgSjbNafTIJlKmZnPjdWkJSC1
cfRmCoImM7dCMwLLJ7qMTSoT62l7OZKbQlpUyDO3guE98sDqnDw/1luLtwIDAQAB
AoGBAKUbnlzvGQPXic/xOY+ZgJuThqX/fngiDQCrgz55qtuRwuELQ8XbOlxDl1ln
tIpv2JyYffE6rDukgOH0QOJ3Bjw8o6ejQZPiAXdIMOJQ3QHgSfFJPvFvnzB7jiCC
8bQLIXgO3GaWjGlP34LBKxcYaaR4exgCMZg0Q/X9HEnzSwPRAkEA9uOt9O9xA9Un
4ta9LgiLNQ1IZG4BaxSkUp70lgJc6dxAlkZwS+3nQB3xtsjPwr1di8xF3E1pAUkt
sn70lbUSxQJBANKj9yFLBM7NRTNSBU3PwH2sxgwwz6i156xNStBcji0zZ/3ixsxd
DusO2kwxLBLxxPbBsxV79A7yhaq9eylTnEsCQQC9fSn6n/vhsSwX0jEIr84IPdWe
H0A/a2xjbVTT/aRKaZ24uP9fh4zBjToDzESJdsXhkjrcRx2cuwmzwfT/IibxAkEA
pykaEODA8wDxvtWDggmx38pB7SC7W07oiNNZ4NritbpK96+FRl8/XIkP8lE/gdU+
EvkLDqystUP/kc0HNXe12wJAa8MUGKrA342qJ4w896KqxuF+L9/6RO0p4Dvpw+n/
73D5zeLL0qK0e8+KS2y2+nOKBrj76ypspxSsMBvVCtn0vQ==
-----END RSA PRIVATE KEY-----`,
		},
	}

	for _, tc := range tcs {
		_, err := KeyImport(tc.algorithm, tc.key)
		assert.NoError(t, err, "KeyImport failed")
	}

	_, err := KeyImport("unsupported", "123456")
	assert.Error(t, err, "KeyImport failed")
}

func TestKeyGenerate(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.EcdsaP256,
		},
		{
			algorithm: types.Rsa1024,
		},
		{
			algorithm: types.Pbkdf2Sha256,
		},
		{
			algorithm: types.Argon2,
		},
	}

	for _, tc := range tcs {
		_, err := KeyGenerate(tc.algorithm)
		assert.NoError(t, err, "KeyGenerate failed")
	}

	_, err := KeyGenerate("unsupported")
	assert.Error(t, err, "KeyGenerate failed")
}
