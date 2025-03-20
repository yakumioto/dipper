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

type KeyImpl struct {
	inputKey  []byte
	expendKey []byte
	nonceSize int
	algorithm types.Algorithm
}

func (k *KeyImpl) Algorithm() types.Algorithm {
	return k.algorithm
}

func (k *KeyImpl) Export() ([]byte, error) {
	return k.inputKey, nil
}

func (k *KeyImpl) SKI() []byte {
	sha := sha256.New()
	sha.Write(k.inputKey)
	return sha.Sum(nil)
}

func (k *KeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) Sign(msg []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (k *KeyImpl) Verify(msg, signature []byte) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (k *KeyImpl) Encrypt(plaintext []byte) ([]byte, error) {
	nonce, err := utils.RandomSize(k.nonceSize)
	if err != nil {
		return nil, fmt.Errorf("chacha20: encrypt failed to generate random nonce: %w", err)
	}

	aead, err := chacha20.NewUnauthenticatedCipher(k.expendKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("chacha20: encrypt failed to create cipher: %w", err)
	}

	ciphertextBytes := make([]byte, len(plaintext))
	aead.XORKeyStream(ciphertextBytes, plaintext)

	payload := make([]byte, 0, len(nonce)+len(ciphertextBytes))
	payload = append(payload, nonce...)
	payload = append(payload, ciphertextBytes...)

	data := bytes.NewBuffer(nil)
	data.WriteString(k.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return data.Bytes(), nil
}

func (k *KeyImpl) Decrypt(ciphertext []byte) ([]byte, error) {
	dataStr := string(ciphertext)
	parts := strings.SplitN(dataStr, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("chacha20: invalid encrypted data structure")
	}

	algorithm, payload := parts[0], parts[1]

	if algorithm != k.algorithm {
		return nil, fmt.Errorf("chacha20: invalid algorithm type: %s", algorithm)
	}

	encryptedPayload, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("chacha20: decrypt failed to decode base64: %w", err)
	}

	if len(encryptedPayload) < k.nonceSize {
		return nil, errors.New("chacha20: ciphertext too short")
	}

	nonce, ciphertextBytes := encryptedPayload[:k.nonceSize], encryptedPayload[k.nonceSize:]

	aead, err := chacha20.NewUnauthenticatedCipher(k.expendKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("chacha20: decrypt failed to create cipher: %w", err)
	}

	plaintextBytes := make([]byte, len(ciphertextBytes))
	aead.XORKeyStream(plaintextBytes, ciphertextBytes)

	return plaintextBytes, nil
}

type KeyImportImpl struct{}

func (k *KeyImportImpl) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option) (key.Key, error) {
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

	return &KeyImpl{
		inputKey:  keyBytes,
		expendKey: extendKey,
		nonceSize: nonceSize,
		algorithm: alg,
	}, nil
}
