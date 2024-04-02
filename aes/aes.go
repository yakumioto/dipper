package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/yakumioto/go-crypto-suite/key"
	"github.com/yakumioto/go-crypto-suite/types"
	"github.com/yakumioto/go-crypto-suite/utils"
)

type CbcKeyImpl[T types.DataType] struct {
	key       []byte
	algorithm types.Algorithm
}

func (a *CbcKeyImpl[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(a.algorithm)
}

func (a *CbcKeyImpl[T]) Bytes() (key T, err error) {
	return T(a.key), nil
}

func (a *CbcKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(a.key)

	return T(utils.ToHexString(sha.Sum(nil)))
}

func (a *CbcKeyImpl[T]) PublicKey() (key.Key[T], error) {
	return nil, errors.New("aes-cbc: unsupported method")
}

func (a *CbcKeyImpl[T]) Sign(_ T) (T, error) {
	return T(""), errors.New("aes-cbc: unsupported method")
}

func (a *CbcKeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, errors.New("aes-cbc: unsupported method")
}

func (a *CbcKeyImpl[T]) Encrypt(plaintext T) (T, error) {
	paddedText := utils.Pkcs7Padding[T](plaintext, aes.BlockSize)

	iv, err := utils.RandomSize(aes.BlockSize)
	if err != nil {
		return T(""), fmt.Errorf("aes-cbc: encrypt failed to generate random iv: %w", err)
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("aes-cbc: encrypt failed to create aes cipher: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	dst := make([]byte, len(paddedText))
	mode.CryptBlocks(dst, paddedText)

	payload := make([]byte, 0, len(iv)+len(dst))
	payload = append(payload, iv...)
	payload = append(payload, dst...)

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(a.algorithm))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (a *CbcKeyImpl[T]) Decrypt(ciphertext T) (T, error) {
	dataBytes := utils.ToString(ciphertext)
	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("aes-cbc: invalid encrypted data structure")
	}

	algorithmType, payload := parts[0], parts[1]

	algorithm, err := strconv.Atoi(algorithmType)
	if err != nil {
		return T(""), errors.New("aes-cbc: algorithm type is not a number")
	}

	if algorithm != a.algorithm {
		return T(""), fmt.Errorf("aes-cbc: invalid algorithm type: %s", types.GetTypeByAlgorithm(algorithm))
	}

	encryptedPayload, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return T(""), fmt.Errorf("aes-cbc: decrypt failed to decode base64: %w", err)
	}

	if len(encryptedPayload) < aes.BlockSize {
		return T(""), errors.New("aes-cbc: ciphertext too short")
	}

	iv := encryptedPayload[:aes.BlockSize]
	ciphertextBytes := encryptedPayload[aes.BlockSize:]

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("aes-cbc: cipher creation error: %w", err)
	}

	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return T(""), errors.New("aes-cbc: ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedText := make([]byte, len(ciphertextBytes))
	mode.CryptBlocks(paddedText, ciphertextBytes)

	return utils.Pkcs7UnPadding(T(paddedText))
}

type GcmKeyImpl[T types.DataType] struct {
	key       []byte
	algorithm types.Algorithm
}

func (a *GcmKeyImpl[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(a.algorithm)
}

func (a *GcmKeyImpl[T]) Bytes() (key T, err error) {
	return T(a.key), nil
}

func (a *GcmKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(a.key)

	return T(utils.ToHexString(sha.Sum(nil)))
}

func (a *GcmKeyImpl[T]) PublicKey() (key.Key[T], error) {
	return nil, errors.New("aes-gcm: unsupported method")
}

func (a *GcmKeyImpl[T]) Sign(_ T) (T, error) {
	return T(""), errors.New("aes-gcm: unsupported method")
}

func (a *GcmKeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, errors.New("aes-gcm: unsupported method")
}

func (a *GcmKeyImpl[T]) Encrypt(plaintext T) (T, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: new aes cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: new gcm cipher error: %w", err)
	}

	nonce, err := utils.RandomSize(gcm.NonceSize())
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: failed to generate random nonce: %w", err)
	}

	sealedData := gcm.Seal(nil, nonce, utils.ToBytes(plaintext), nil)

	payload := make([]byte, 0, len(nonce)+len(sealedData))
	payload = append(payload, nonce...)
	payload = append(payload, sealedData...)

	data := bytes.NewBufferString(strconv.Itoa(a.algorithm) + ".")
	if _, err := data.WriteString(base64.RawStdEncoding.EncodeToString(payload)); err != nil {
		return T(""), fmt.Errorf("aes-gcm: failed to encode payload: %w", err)
	}

	return T(data.Bytes()), nil
}

func (a *GcmKeyImpl[T]) Decrypt(ciphertext T) (T, error) {
	dataBytes := utils.ToString(ciphertext)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("aes-gcm: invalid encrypted data structure")
	}

	algorithmType, payload := parts[0], parts[1]

	algorithm, err := strconv.Atoi(algorithmType)
	if err != nil {
		return T(""), errors.New("aes-gcm: algorithm type is not a number")
	}

	if algorithm != a.algorithm {
		return T(""), fmt.Errorf("aes-gcm: invalid algorithm type: %s", types.GetTypeByAlgorithm(algorithm))
	}

	encryptedPayload, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: decrypt failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: new aes cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: new gcm cipher error: %w", err)
	}

	if len(encryptedPayload) < gcm.NonceSize() {
		return T(""), errors.New("aes-gcm: ciphertext too short")
	}

	nonce, ciphertextBytes := encryptedPayload[:gcm.NonceSize()], encryptedPayload[gcm.NonceSize():]

	decryptedData, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return T(""), fmt.Errorf("aes-gcm: failed to decrypt data: %w", err)
	}

	return T(decryptedData), nil
}

type KeyImportImpl[T types.DataType] struct{}

func (a *KeyImportImpl[T]) KeyImport(raw interface{}, alg types.Algorithm) (key.Key[T], error) {
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
		return nil, fmt.Errorf("aes: invalid algorithm: %v", types.GetTypeByAlgorithm(alg))
	}

	extendKey := utils.ExtendKey(keyBytes, keyLen)

	switch alg {
	case types.AesCbc128, types.AesCbc192, types.AesCbc256:
		return &CbcKeyImpl[T]{algorithm: alg, key: extendKey}, nil
	case types.AesGcm128, types.AesGcm192, types.AesGcm256:
		return &GcmKeyImpl[T]{algorithm: alg, key: extendKey}, nil
	default:
		panic("unhandled default case")
	}
}
