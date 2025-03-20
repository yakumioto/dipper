package dipper

import (
	"fmt"

	"github.com/yakumioto/dipper/aes"
	"github.com/yakumioto/dipper/argon2"
	"github.com/yakumioto/dipper/ecdsa"
	"github.com/yakumioto/dipper/hmac"
	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/pbkdf2"
	"github.com/yakumioto/dipper/rsa"
	"github.com/yakumioto/dipper/types"
)

// KeyImport is a function that imports a cryptographic key based on a given raw data and algorithm.
// It supports HMAC SHA, AES CBC, AES GCM, ECDSA, and RSA algorithms.
// If the algorithm is not supported, it returns an error.
func KeyImport(alg types.Algorithm, raw any, opts ...key.Option) (key.Key, error) {
	switch alg {
	case types.HmacSha256, types.HmacSha512:
		return new(hmac.ShaKeyImportImpl).KeyImport(raw, alg, opts...)
	case types.AesCbc128, types.AesCbc192, types.AesCbc256, types.AesGcm128, types.AesGcm192, types.AesGcm256:
		return new(aes.KeyImportImpl).KeyImport(raw, alg, opts...)
	case types.EcdsaP256, types.EcdsaP384:
		return new(ecdsa.KeyImportImpl).KeyImport(raw, alg, opts...)
	case types.Rsa1024, types.Rsa2048, types.Rsa4096:
		return new(rsa.KeyImportImpl).KeyImport(raw, alg, opts...)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", alg)
	}
}

// KeyGenerate is a function that generates a cryptographic key based on a given algorithm.
// It supports ECDSA and RSA algorithms.
// If the algorithm is not supported, it returns an error.
func KeyGenerate(alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	switch alg {
	case types.EcdsaP256, types.EcdsaP384:
		return new(ecdsa.KeyGeneratorImpl).KeyGen(alg, opts...)
	case types.Rsa1024, types.Rsa2048, types.Rsa4096:
		return new(rsa.KeyGeneratorImpl).KeyGen(alg, opts...)
	case types.Pbkdf2Sha256, types.Pbkdf2Sha512:
		return new(pbkdf2.KeyGeneratorImpl).KeyGen(alg, opts...)
	case types.Argon2:
		return new(argon2.KeyGeneratorImpl).KeyGen(alg, opts...)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", alg)
	}
}
