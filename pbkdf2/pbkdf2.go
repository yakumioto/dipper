package pbkdf2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/yakumioto/go-crypto-suite/key"
	"github.com/yakumioto/go-crypto-suite/types"
	"github.com/yakumioto/go-crypto-suite/utils"
)

var (
	ErrUnsupportedMethod = errors.New("pbkdf2: unsupported method")
)

type KeyImpl[T types.DataType] struct {
	algorithm  types.Algorithm
	saltSize   int
	iterations int
	keyLen     int
	digestFunc func() hash.Hash
}

func WithIterations[T types.DataType](iterations int) key.Option[T] {
	return func(k key.Key[T]) error {
		if _, ok := k.(*KeyImpl[T]); ok {
			if iterations <= 0 {
				return nil
			}

			k.(*KeyImpl[T]).iterations = iterations
			return nil
		}
		return errors.New("pbkdf2: invalid key type")
	}
}

func WithSaltSize[T types.DataType](saltSize int) key.Option[T] {
	return func(k key.Key[T]) error {
		if _, ok := k.(*KeyImpl[T]); ok {
			if saltSize <= 0 {
				return nil
			}

			k.(*KeyImpl[T]).saltSize = saltSize
			return nil
		}

		return errors.New("pbkdf2: invalid key type")
	}
}

func (k *KeyImpl[T]) Algorithm() types.Algorithm {
	return k.algorithm
}

func (k *KeyImpl[T]) Export() (key T, err error) {
	return T(""), ErrUnsupportedMethod
}

func (k *KeyImpl[T]) SKI() T {
	return T("")
}

func (k *KeyImpl[T]) PublicKey() (key.Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl[T]) Sign(msg T) (signature T, err error) {
	saltBytes, err := utils.RandomSize(k.saltSize)
	if err != nil {
		return T(""), fmt.Errorf("pbkdf2: failed to generate random salt: %w", err)
	}

	digest := pbkdf2.Key(utils.ToBytes(msg), saltBytes, k.iterations, k.keyLen, k.digestFunc)

	payload := fmt.Sprintf("%d$%s$%s",
		k.iterations,
		base64.RawStdEncoding.EncodeToString(saltBytes),
		base64.RawStdEncoding.EncodeToString(digest),
	)

	data := bytes.NewBuffer(nil)
	data.WriteString(k.algorithm)
	data.WriteString(".")
	data.WriteString(payload)

	return T(data.Bytes()), nil
}

func (k *KeyImpl[T]) Verify(msg, signature T) (bool, error) {
	dataBytes := utils.ToString(signature)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return false, errors.New("pbkdf2: invalid signature data structure")
	}

	algorithm, encodedSignature := parts[0], parts[1]

	if algorithm != k.algorithm {
		return false, fmt.Errorf("pbkdf2: invalid algorithm type: %s", algorithm)
	}

	parts = strings.SplitN(encodedSignature, "$", 3)
	if len(parts) != 3 {
		return false, errors.New("pbkdf2: invalid signature payload data structure")
	}

	iterations, salt, digest := parts[0], parts[1], parts[2]

	providedIterations, err := strconv.Atoi(iterations)
	if err != nil {
		return false, errors.New("pbkdf2: provided iterations is not a number")
	}

	providedSalt, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, fmt.Errorf("pbkdf2: decrypt provided salt failed to decode base64: %w", err)
	}

	providedDigest, err := base64.RawStdEncoding.DecodeString(digest)
	if err != nil {
		return false, fmt.Errorf("pbkdf2: decrypt provided digest failed to decode base64: %w", err)
	}

	computedDigest := pbkdf2.Key(utils.ToBytes(msg), providedSalt, providedIterations, k.keyLen, k.digestFunc)

	return hmac.Equal(providedDigest, computedDigest), nil
}

func (k *KeyImpl[T]) Encrypt(_ T) (ciphertext T, err error) {
	return T(""), ErrUnsupportedMethod
}

func (k *KeyImpl[T]) Decrypt(_ T) (plaintext T, err error) {
	return T(""), ErrUnsupportedMethod
}

type KeyGeneratorImpl[T types.DataType] struct{}

func (k *KeyGeneratorImpl[T]) KeyGen(alg types.Algorithm, opts ...key.Option[T]) (key.Key[T], error) {
	ki := &KeyImpl[T]{
		algorithm:  alg,
		saltSize:   16,
		iterations: 10000,
	}

	for _, opt := range opts {
		if err := opt(ki); err != nil {
			return nil, err
		}
	}

	switch alg {
	case types.Pbkdf2Sha256:
		ki.digestFunc = sha256.New
		ki.keyLen = sha256.Size

		return ki, nil
	case types.Pbkdf2Sha512:
		ki.digestFunc = sha512.New
		ki.keyLen = sha512.Size

		return ki, nil
	default:
		return nil, fmt.Errorf("pbkdf2: invalid algorithm: %v", alg)
	}
}
