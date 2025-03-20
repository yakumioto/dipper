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

	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

var (
	ErrUnsupportedMethod = errors.New("pbkdf2: unsupported method")
)

type KeyImpl struct {
	algorithm  types.Algorithm
	saltSize   int
	iterations int
	keyLen     int
	digestFunc func() hash.Hash
}

func WithIterations(iterations int) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if iterations <= 0 {
				return nil
			}
			ki.iterations = iterations
			return nil
		}
		return errors.New("pbkdf2: invalid key type")
	}
}

func WithSaltSize(saltSize int) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if saltSize <= 0 {
				return nil
			}
			ki.saltSize = saltSize
			return nil
		}
		return errors.New("pbkdf2: invalid key type")
	}
}

func (k *KeyImpl) Algorithm() types.Algorithm {
	return k.algorithm
}

func (k *KeyImpl) Export() ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) SKI() []byte {
	return nil
}

func (k *KeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) Sign(msg []byte) ([]byte, error) {
	saltBytes, err := utils.RandomSize(k.saltSize)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: failed to generate random salt: %w", err)
	}

	digest := pbkdf2.Key(msg, saltBytes, k.iterations, k.keyLen, k.digestFunc)

	payload := fmt.Sprintf("%d$%s$%s",
		k.iterations,
		base64.RawStdEncoding.EncodeToString(saltBytes),
		base64.RawStdEncoding.EncodeToString(digest),
	)

	data := bytes.NewBuffer(nil)
	data.WriteString(k.algorithm)
	data.WriteString(".")
	data.WriteString(payload)

	return data.Bytes(), nil
}

func (k *KeyImpl) Verify(msg, signature []byte) (bool, error) {
	dataStr := string(signature)
	parts := strings.SplitN(dataStr, ".", 2)
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

	computedDigest := pbkdf2.Key(msg, providedSalt, providedIterations, k.keyLen, k.digestFunc)

	return hmac.Equal(providedDigest, computedDigest), nil
}

func (k *KeyImpl) Encrypt([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) Decrypt([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

type KeyGeneratorImpl struct{}

func (k *KeyGeneratorImpl) KeyGen(alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	ki := &KeyImpl{
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
