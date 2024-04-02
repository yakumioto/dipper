package key

import "github.com/yakumioto/go-crypto-suite/types"

// Key is an interface that represents a cryptographic key.
// It provides methods for getting the algorithm type, byte representation, subject key identifier (SKI),
// public key, signing, verifying, encrypting, and decrypting.
type Key[T types.DataType] interface {
	AlgorithmType() types.AlgorithmType
	Bytes() (key T, err error)
	SKI() T
	PublicKey() (Key[T], error)
	Sign(msg T) (signature T, err error)
	Verify(msg, signature T) (bool, error)
	Encrypt(plaintext T) (ciphertext T, err error)
	Decrypt(ciphertext T) (plaintext T, err error)
}

// Generator is an interface that represents a cryptographic key generator.
// It provides a method for generating a key based on a given algorithm.
type Generator[T types.DataType] interface {
	KeyGen(alg types.Algorithm) (Key[T], error)
}

// Importer is an interface that represents a cryptographic key importer.
// It provides a method for importing a key based on a given raw data and algorithm.
type Importer[T types.DataType] interface {
	KeyImport(raw interface{}, alg types.Algorithm) (Key[T], error)
}
