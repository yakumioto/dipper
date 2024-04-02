package crypto

import (
	"fmt"

	"github.com/yakumioto/go-crypto-suite/aes"
	"github.com/yakumioto/go-crypto-suite/ecdsa"
	"github.com/yakumioto/go-crypto-suite/hmac"
	"github.com/yakumioto/go-crypto-suite/key"
	"github.com/yakumioto/go-crypto-suite/rsa"
	"github.com/yakumioto/go-crypto-suite/types"
)

// KeyImport is a function that imports a cryptographic key based on a given raw data and algorithm.
// It supports HMAC SHA, AES CBC, AES GCM, ECDSA, and RSA algorithms.
// If the algorithm is not supported, it returns an error.
func KeyImport[T types.DataType](raw interface{}, alg types.Algorithm) (key.Key[T], error) {
	switch alg {
	case types.HmacSha256, types.HmacSha512:
		return new(hmac.ShaKeyImportImpl[T]).KeyImport(raw, alg)
	case types.AesCbc128, types.AesCbc192, types.AesCbc256, types.AesGcm128, types.AesGcm192, types.AesGcm256:
		return new(aes.KeyImportImpl[T]).KeyImport(raw, alg)
	case types.EcdsaP256, types.EcdsaP384:
		return new(ecdsa.KeyImportImpl[T]).KeyImport(raw, alg)
	case types.Rsa1024, types.Rsa2048, types.Rsa4096:
		return new(rsa.KeyImportImpl[T]).KeyImport(raw, alg)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", types.GetTypeByAlgorithm(alg))
	}
}

// KeyGenerate is a function that generates a cryptographic key based on a given algorithm.
// It supports ECDSA and RSA algorithms.
// If the algorithm is not supported, it returns an error.
func KeyGenerate[T types.DataType](alg types.Algorithm) (key.Key[T], error) {
	switch alg {
	case types.EcdsaP256, types.EcdsaP384:
		return new(ecdsa.KeyGeneratorImpl[T]).KeyGen(alg)
	case types.Rsa1024, types.Rsa2048, types.Rsa4096:
		return new(rsa.KeyGeneratorImpl[T]).KeyGen(alg)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", types.GetTypeByAlgorithm(alg))
	}
}
