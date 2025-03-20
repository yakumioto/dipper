package key

import "github.com/yakumioto/dipper/types"

// Key is an interface that represents a cryptographic key.
// It provides methods for getting the algorithm type, byte representation, subject key identifier (SKI),
// public key, signing, verifying, encrypting, and decrypting.
type Key interface {
	Algorithm() types.Algorithm
	Export() (key []byte, err error)
	SKI() []byte
	PublicKey() (Key, error)
	Sign(msg []byte) (signature []byte, err error)
	Verify(msg, signature []byte) (bool, error)
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

// Option is a function type that represents an option for a key.
type Option func(Key) error

// Generator is an interface that represents a cryptographic key generator.
// It provides a method for generating a key based on a given algorithm.
type Generator interface {
	KeyGen(alg types.Algorithm, opts ...Option) (Key, error)
}

// Importer is an interface that represents a cryptographic key importer.
// It provides a method for importing a key based on a given raw data and algorithm.
type Importer interface {
	KeyImport(raw interface{}, alg types.Algorithm, opts ...Option) (Key, error)
}
