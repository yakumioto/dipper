package crypto

import "fmt"

// DataType is an interface that represents the data type of a cryptographic key.
// It can be either a byte slice or a string.
type DataType interface {
	~[]byte | ~string
}

// Key is an interface that represents a cryptographic key.
// It provides methods for getting the algorithm type, byte representation, subject key identifier (SKI),
// public key, signing, verifying, encrypting, and decrypting.
type Key[T DataType] interface {
	AlgorithmType() AlgorithmType
	Bytes() (key T, err error)
	SKI() T
	PublicKey() (Key[T], error)
	Sign(msg T) (signature T, err error)
	Verify(msg, signature T) (bool, error)
	Encrypt(plaintext T) (ciphertext T, err error)
	Decrypt(ciphertext T) (plaintext T, err error)
}

// KeyGenerator is an interface that represents a cryptographic key generator.
// It provides a method for generating a key based on a given algorithm.
type KeyGenerator[T DataType] interface {
	KeyGen(alg Algorithm) (Key[T], error)
}

// KeyImporter is an interface that represents a cryptographic key importer.
// It provides a method for importing a key based on a given raw data and algorithm.
type KeyImporter[T DataType] interface {
	KeyImport(raw interface{}, alg Algorithm) (Key[T], error)
}

// KeyImport is a function that imports a cryptographic key based on a given raw data and algorithm.
// It supports HMAC SHA, AES CBC, AES GCM, ECDSA, and RSA algorithms.
// If the algorithm is not supported, it returns an error.
func KeyImport[T DataType](raw interface{}, alg Algorithm) (Key[T], error) {
	switch alg {
	case HmacSha256, HmacSha512:
		return new(hmacShaKeyImportImpl[T]).KeyImport(raw, alg)
	case AesCbc128, AesCbc192, AesCbc256, AesGcm128, AesGcm192, AesGcm256:
		return new(aesKeyImportImpl[T]).KeyImport(raw, alg)
	case EcdsaP256, EcdsaP384:
		return new(ecdsaKeyImportImpl[T]).KeyImport(raw, alg)
	case Rsa1024, Rsa2048, Rsa4096:
		return new(rsaKeyImportImpl[T]).KeyImport(raw, alg)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", GetTypeByAlgorithm(alg))
	}
}

// KeyGenerate is a function that generates a cryptographic key based on a given algorithm.
// It supports ECDSA and RSA algorithms.
// If the algorithm is not supported, it returns an error.
func KeyGenerate[T DataType](alg Algorithm) (Key[T], error) {
	switch alg {
	case EcdsaP256, EcdsaP384:
		return new(ecdsaKeyGeneratorImpl[T]).KeyGen(alg)
	case Rsa1024, Rsa2048, Rsa4096:
		return new(rsaKeyGeneratorImpl[T]).KeyGen(alg)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", GetTypeByAlgorithm(alg))
	}
}
