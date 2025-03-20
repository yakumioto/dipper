package argon2

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

const (
	MethodArgon2i  = "argon2i"
	MethodArgon2id = "argon2id"
)

var (
	ErrUnsupportedMethod = errors.New("argon2: unsupported method")
)

func WithMethod(method string) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if method != MethodArgon2i && method != MethodArgon2id {
				return fmt.Errorf("argon2: invalid method: %s", method)
			}

			ki.method = method
			return nil
		}
		return errors.New("argon2: invalid key type")
	}
}

func WithSaltSize(size int) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if size <= 0 {
				return nil
			}

			ki.saltSize = size
			return nil
		}
		return errors.New("argon2: invalid key type")
	}
}

func WithTime(time uint32) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if time == 0 {
				return nil
			}
			ki.time = time
			return nil
		}
		return errors.New("argon2: invalid key type")
	}
}

func WithMemory(memory uint32) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if memory == 0 {
				return nil
			}
			ki.memory = memory
			return nil
		}
		return errors.New("argon2: invalid key type")
	}
}

func WithThreads(threads uint8) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if threads == 0 {
				return nil
			}
			ki.threads = threads
			return nil
		}
		return errors.New("argon2: invalid key type")
	}
}

func WithLength(length uint32) key.Option {
	return func(k key.Key) error {
		if ki, ok := k.(*KeyImpl); ok {
			if length <= 0 {
				return nil
			}
			ki.length = length
			return nil
		}
		return errors.New("argon2: invalid key type")
	}
}

type KeyImpl struct {
	algorithm types.Algorithm
	method    string
	saltSize  int
	time      uint32
	memory    uint32
	threads   uint8
	length    uint32
}

func (k *KeyImpl) Algorithm() types.Algorithm {
	return k.algorithm
}

func (k *KeyImpl) Export() ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) SKI() []byte {
	return []byte("")
}

func (k *KeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) Sign(msg []byte) ([]byte, error) {
	saltBytes, err := utils.RandomSize(k.saltSize)
	if err != nil {
		return nil, fmt.Errorf("argon2: failed to generate random salt: %w", err)
	}

	var digest []byte
	if k.method == MethodArgon2i {
		digest = argon2.Key(msg, saltBytes, k.time, k.memory, k.threads, k.length)
	} else {
		digest = argon2.IDKey(msg, saltBytes, k.time, k.memory, k.threads, k.length)
	}

	payload := fmt.Sprintf("%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		k.method,
		argon2.Version,
		k.memory,
		k.time,
		k.threads,
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
	dataBytes := string(signature)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return false, errors.New("argon2: invalid signature data structure")
	}

	algorithm, encodedSignature := parts[0], parts[1]

	if algorithm != k.algorithm {
		return false, fmt.Errorf("argon2: invalid algorithm type: %s", algorithm)
	}

	parts = strings.SplitN(encodedSignature, "$", 5)
	if len(parts) != 5 {
		return false, errors.New("argon2: invalid signature payload data structure")
	}

	method, version, params, salt, digest := parts[0], parts[1], parts[2], parts[3], parts[4]
	var (
		v            int
		memory, time uint32
		threads      uint8
		err          error
	)

	_, err = fmt.Sscanf(version, "v=%d", &v)
	if err != nil {
		return false, fmt.Errorf("argon2: failed to parse version: %w", err)
	}

	if v != argon2.Version {
		return false, fmt.Errorf("argon2: invalid version: %d", v)
	}

	_, err = fmt.Sscanf(params, "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, fmt.Errorf("argon2: failed to parse params: %w", err)
	}

	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, fmt.Errorf("argon2: failed to decode salt: %w", err)
	}

	providedDigest, err := base64.RawStdEncoding.DecodeString(digest)
	if err != nil {
		return false, fmt.Errorf("argon2: failed to decode digest: %w", err)
	}

	var computedDigest []byte
	if method == MethodArgon2i {
		computedDigest = argon2.Key(msg, saltBytes, time, memory, threads, k.length)
	} else {
		computedDigest = argon2.IDKey(msg, saltBytes, time, memory, threads, k.length)
	}

	return hmac.Equal(providedDigest, computedDigest), nil
}

func (k *KeyImpl) Encrypt(plaintext []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) Decrypt(ciphertext []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

type KeyGeneratorImpl struct{}

func (k *KeyGeneratorImpl) KeyGen(alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	ki := &KeyImpl{
		algorithm: alg,
		method:    MethodArgon2id,
		saltSize:  16,
		time:      1,
		memory:    64 * 1024,
		threads:   4,
		length:    32,
	}

	for _, opt := range opts {
		if err := opt(ki); err != nil {
			return nil, err
		}
	}

	return ki, nil
}
