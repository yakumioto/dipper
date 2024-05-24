package chacha20

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20"

	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

var (
	ErrUnsupportedMethod = errors.New("chacha20: unsupported method")
)

type KeyImpl[T types.DataType] struct {
	inputKey  []byte
	expendKey []byte
	nonceSize int
	algorithm types.Algorithm
}

func (k *KeyImpl[T]) Algorithm() types.Algorithm {
	return k.algorithm
}

func (k *KeyImpl[T]) Export() (key T, err error) {
	return T(k.inputKey), nil
}

func (k *KeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(k.inputKey)

	return T(utils.ToHexString(sha.Sum(nil)))
}

func (k *KeyImpl[T]) PublicKey() (key.Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl[T]) Sign(_ T) (signature T, err error) {
	return T(""), ErrUnsupportedMethod
}

func (k *KeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (k *KeyImpl[T]) Encrypt(plaintext T) (ciphertext T, err error) {
	nonce, err := utils.RandomSize(k.nonceSize)
	if err != nil {
		return T(""), fmt.Errorf("chacha20: encrypt failed to generate random nonce: %w", err)
	}

	aead, err := chacha20.NewUnauthenticatedCipher(k.expendKey, nonce)
	if err != nil {
		return T(""), fmt.Errorf("chacha20: encrypt failed to create cipher: %w", err)
	}

	plaintextBytes := utils.ToBytes(plaintext)
	ciphertextBytes := make([]byte, len(plaintextBytes))
	aead.XORKeyStream(ciphertextBytes, plaintextBytes)

	payload := make([]byte, 0, len(nonce)+len(ciphertextBytes))
	payload = append(payload, nonce...)
	payload = append(payload, ciphertextBytes...)

	data := bytes.NewBuffer(nil)
	data.WriteString(k.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return T(data.String()), nil
}

func (k *KeyImpl[T]) Decrypt(ciphertext T) (plaintext T, err error) {
	dataBytes := utils.ToString(ciphertext)
	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("chacha20:  invalid encrypted data structure")
	}

	algorithm, payload := parts[0], parts[1]

	if algorithm != k.algorithm {
		return T(""), fmt.Errorf("chacha20: invalid algorithm type: %s", algorithm)
	}

	encryptedPayload, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return T(""), fmt.Errorf("chacha20: decrypt failed to decode base64: %w", err)
	}

	if len(encryptedPayload) < k.nonceSize {
		return T(""), errors.New("chacha20: ciphertext too short")
	}

	nonce, ciphertextBytes := encryptedPayload[:k.nonceSize], encryptedPayload[k.nonceSize:]

	aead, err := chacha20.NewUnauthenticatedCipher(k.expendKey, nonce)
	if err != nil {
		return T(""), fmt.Errorf("chacha20: decrypt failed to create cipher: %w", err)
	}

	plaintextBytes := make([]byte, len(ciphertextBytes))
	aead.XORKeyStream(plaintextBytes, ciphertextBytes)

	return T(plaintextBytes), nil
}

type KeyImportImpl[T types.DataType] struct{}

func (k *KeyImportImpl[T]) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option[T]) (key.Key[T], error) {
	keyBytes, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("chacha20: key import failed to convert key: %w", err)
	}

	var nonceSize int
	switch alg {
	case types.Chacha20:
		nonceSize = chacha20.NonceSize
	case types.XChacha20:
		nonceSize = chacha20.NonceSizeX
	default:
		return nil, fmt.Errorf("chacha20: invalid algorithm: %v", alg)
	}

	extendKey := utils.ExtendKey(keyBytes, chacha20.KeySize)

	return &KeyImpl[T]{
		inputKey:  keyBytes,
		expendKey: extendKey,
		nonceSize: nonceSize,
		algorithm: alg,
	}, nil
}
