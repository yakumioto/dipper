package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

var (
	ErrUnsupportedMethod = errors.New("aes: unsupported method")
)

type CbcKeyImpl struct {
	inputKey  []byte
	extendKey []byte
	algorithm types.Algorithm
}

func (a *CbcKeyImpl) Algorithm() types.Algorithm {
	return a.algorithm
}

func (a *CbcKeyImpl) Export() ([]byte, error) {
	return a.inputKey, nil
}

func (a *CbcKeyImpl) SKI() []byte {
	sha := sha256.New()
	sha.Write(a.inputKey)

	return []byte(hex.EncodeToString(sha.Sum(nil)))
}

func (a *CbcKeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (a *CbcKeyImpl) Sign(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (a *CbcKeyImpl) Verify(_, _ []byte) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (a *CbcKeyImpl) Encrypt(plaintext []byte) ([]byte, error) {
	paddedText := utils.Pkcs7Padding(plaintext, aes.BlockSize)

	iv, err := utils.RandomSize(aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: encrypt failed to generate random iv: %w", err)
	}

	block, err := aes.NewCipher(a.extendKey)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: encrypt failed to create aes cipher: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	dst := make([]byte, len(paddedText))
	mode.CryptBlocks(dst, paddedText)

	payload := make([]byte, 0, len(iv)+len(dst))
	payload = append(payload, iv...)
	payload = append(payload, dst...)

	data := bytes.NewBuffer(nil)
	data.WriteString(a.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return data.Bytes(), nil
}

func (a *CbcKeyImpl) Decrypt(ciphertext []byte) ([]byte, error) {
	dataBytes := string(ciphertext)
	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("aes-cbc: invalid encrypted data structure")
	}

	algorithm, payload := parts[0], parts[1]

	if algorithm != a.algorithm {
		return nil, fmt.Errorf("aes-cbc: invalid algorithm type: %s", algorithm)
	}

	encryptedPayload, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: decrypt failed to decode base64: %w", err)
	}

	if len(encryptedPayload) < aes.BlockSize {
		return nil, errors.New("aes-cbc: ciphertext too short")
	}

	iv := encryptedPayload[:aes.BlockSize]
	ciphertextBytes := encryptedPayload[aes.BlockSize:]

	block, err := aes.NewCipher(a.extendKey)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: cipher creation error: %w", err)
	}

	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return nil, errors.New("aes-cbc: ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedText := make([]byte, len(ciphertextBytes))
	mode.CryptBlocks(paddedText, ciphertextBytes)

	return utils.Pkcs7UnPadding(paddedText), nil
}

type GcmKeyImpl struct {
	inputKey  []byte
	extendKey []byte
	algorithm types.Algorithm
}

func (a *GcmKeyImpl) Algorithm() types.Algorithm {
	return a.algorithm
}

func (a *GcmKeyImpl) Export() ([]byte, error) {
	return a.inputKey, nil
}

func (a *GcmKeyImpl) SKI() []byte {
	sha := sha256.New()
	sha.Write(a.inputKey)

	return []byte(hex.EncodeToString(sha.Sum(nil)))
}

func (a *GcmKeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (a *GcmKeyImpl) Sign(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (a *GcmKeyImpl) Verify(_, _ []byte) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (a *GcmKeyImpl) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.extendKey)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new aes cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new gcm cipher error: %w", err)
	}

	nonce, err := utils.RandomSize(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to generate random nonce: %w", err)
	}

	sealedData := gcm.Seal(nil, nonce, plaintext, nil)

	payload := make([]byte, 0, len(nonce)+len(sealedData))
	payload = append(payload, nonce...)
	payload = append(payload, sealedData...)

	data := bytes.NewBuffer(nil)
	data.WriteString(a.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return data.Bytes(), nil
}

func (a *GcmKeyImpl) Decrypt(ciphertext []byte) ([]byte, error) {
	dataBytes := string(ciphertext)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("aes-gcm: invalid encrypted data structure")
	}

	algorithm, payload := parts[0], parts[1]

	if algorithm != a.algorithm {
		return nil, fmt.Errorf("aes-gcm: invalid algorithm type: %s", algorithm)
	}

	encryptedPayload, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: decrypt failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(a.extendKey)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new aes cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new gcm cipher error: %w", err)
	}

	if len(encryptedPayload) < gcm.NonceSize() {
		return nil, errors.New("aes-gcm: ciphertext too short")
	}

	nonce, ciphertextBytes := encryptedPayload[:gcm.NonceSize()], encryptedPayload[gcm.NonceSize():]

	decryptedData, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to decrypt data: %w", err)
	}

	return decryptedData, nil
}

type KeyImportImpl struct{}

func (a *KeyImportImpl) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	keyBytes, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("aes: key import failed to convert key: %w", err)
	}

	var keyLen int
	switch alg {
	case types.AesCbc128, types.AesGcm128:
		keyLen = 128 / 8
	case types.AesCbc192, types.AesGcm192:
		keyLen = 192 / 8
	case types.AesCbc256, types.AesGcm256:
		keyLen = 256 / 8
	default:
		return nil, fmt.Errorf("aes: invalid algorithm: %v", alg)
	}

	extendKey := utils.ExtendKey(keyBytes, keyLen)

	switch alg {
	case types.AesCbc128, types.AesCbc192, types.AesCbc256:
		return &CbcKeyImpl{algorithm: alg, inputKey: keyBytes, extendKey: extendKey}, nil
	case types.AesGcm128, types.AesGcm192, types.AesGcm256:
		return &GcmKeyImpl{algorithm: alg, inputKey: keyBytes, extendKey: extendKey}, nil
	default:
		panic("unhandled default case")
	}
}
