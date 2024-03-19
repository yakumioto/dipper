package crypto

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

	"golang.org/x/crypto/pbkdf2"
)

type aesCbcKeyImpl[T DataType] struct {
	key       []byte
	algorithm Algorithm
}

func (a *aesCbcKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(a.algorithm)
}

func (a *aesCbcKeyImpl[T]) Bytes() (key T, err error) {
	return T(a.key), nil
}

func (a *aesCbcKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(a.key)

	return T(toHexString(sha.Sum(nil)))
}

func (a *aesCbcKeyImpl[T]) PublicKey() (Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (a *aesCbcKeyImpl[T]) Sign(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (a *aesCbcKeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (a *aesCbcKeyImpl[T]) Encrypt(plaintext T) (T, error) {
	paddedText := pkcs7Padding[T](plaintext, aes.BlockSize)

	iv, err := RandomSize(aes.BlockSize)
	if err != nil {
		return T(""), fmt.Errorf("encrypt: failed to generate random IV: %w", err)
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("encrypt: failed to create AES cipher: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	dst := make([]byte, len(paddedText))
	mode.CryptBlocks(dst, paddedText)

	payload := make([]byte, 0, len(iv)+len(dst))
	payload = append(payload, iv...)
	payload = append(payload, dst...)

	data := bytes.NewBufferString(strconv.Itoa(int(a.algorithm)) + ".")
	if _, err := data.WriteString(base64.StdEncoding.EncodeToString(payload)); err != nil {
		return T(""), fmt.Errorf("encrypt: failed to encode payload: %w", err)
	}

	return T(data.Bytes()), nil
}

func (a *aesCbcKeyImpl[T]) Decrypt(ciphertext T) (T, error) {
	ciphertextStr := toString(ciphertext)
	parts := strings.SplitN(ciphertextStr, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("invalid encrypted data: expected two parts separated by '.'")
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		return T(""), fmt.Errorf("type conversion error: %w", err)
	}

	if Algorithm(typ) != a.algorithm {
		return T(""), fmt.Errorf("invalid algorithm type: %s", GetTypeByAlgorithm(Algorithm(typ)))
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return T(""), fmt.Errorf("base64 decoding error: %w", err)
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return T(""), errors.New("ciphertext too short")
	}

	iv := ciphertextBytes[:aes.BlockSize]
	srcCiphertextBytes := ciphertextBytes[aes.BlockSize:]

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("cipher creation error: %w", err)
	}

	if len(srcCiphertextBytes)%aes.BlockSize != 0 {
		return T(""), errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedText := make([]byte, len(srcCiphertextBytes))
	mode.CryptBlocks(paddedText, srcCiphertextBytes)

	return pkcs7UnPadding(T(paddedText))
}

type aesGcmKeyImpl[T DataType] struct {
	key       []byte
	algorithm Algorithm
}

func (a *aesGcmKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(a.algorithm)
}

func (a *aesGcmKeyImpl[T]) Bytes() (key T, err error) {
	return T(a.key), nil
}

func (a *aesGcmKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(a.key)

	return T(toHexString(sha.Sum(nil)))
}

func (a *aesGcmKeyImpl[T]) PublicKey() (Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (a *aesGcmKeyImpl[T]) Sign(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (a *aesGcmKeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (a *aesGcmKeyImpl[T]) Encrypt(plaintext T) (T, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("new aes cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return T(""), fmt.Errorf("new GCM cipher error: %w", err)
	}

	nonce, err := RandomSize(gcm.NonceSize())
	if err != nil {
		return T(""), fmt.Errorf("random GCM nonce error: %w", err)
	}

	sealedData := gcm.Seal(nil, nonce, toBytes(plaintext), nil)

	payload := make([]byte, 0, len(nonce)+len(sealedData))
	payload = append(payload, nonce...)
	payload = append(payload, sealedData...)

	data := bytes.NewBufferString(strconv.Itoa(int(a.algorithm)) + ".")
	if _, err := data.WriteString(base64.StdEncoding.EncodeToString(payload)); err != nil {
		return T(""), fmt.Errorf("encrypt: failed to encode payload: %w", err)
	}

	return T(data.Bytes()), nil
}

func (a *aesGcmKeyImpl[T]) Decrypt(ciphertext T) (T, error) {

	dataBytes := toString(ciphertext)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("invalid encrypted data format")
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		return T(""), errors.New("type is not a number")
	}

	if Algorithm(typ) != a.algorithm {
		return T(""), fmt.Errorf("invalid algorithm type: %s", GetTypeByAlgorithm(Algorithm(typ)))
	}

	encryptedData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return T(""), fmt.Errorf("base64 decoding error: %w", err)
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return T(""), fmt.Errorf("new AES cipher error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return T(""), fmt.Errorf("new GCM cipher error: %w", err)
	}

	if len(encryptedData) < gcm.NonceSize() {
		return T(""), fmt.Errorf("encrypted data too short, missing nonce")
	}

	nonce, encryptedData := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]

	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return T(""), fmt.Errorf("GCM decryption error: %w", err)
	}

	return T(decryptedData), nil
}

type aesKeyImportImpl[T DataType] struct{}

func (a *aesKeyImportImpl[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
	key, err := checkAndConvertKey(raw)
	if err != nil {
		return nil, fmt.Errorf("key import: %w", err)
	}

	var keyLen int
	switch alg {
	case AesCbc128, AesGcm128:
		keyLen = 128 / 8
	case AesCbc192, AesGcm192:
		keyLen = 192 / 8
	case AesCbc256, AesGcm256:
		keyLen = 256 / 8
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", GetTypeByAlgorithm(alg))
	}

	if len(key) != keyLen {
		key = pbkdf2.Key(key, key /* use a real salt here */, 1000, keyLen, sha256.New)
	}

	switch alg {
	case AesCbc128, AesCbc192, AesCbc256:
		return &aesCbcKeyImpl[T]{algorithm: alg, key: key}, nil
	case AesGcm128, AesGcm192, AesGcm256:
		return &aesGcmKeyImpl[T]{algorithm: alg, key: key}, nil
	default:
		// This case should never be hit due to the default case in the first switch,
		// but it's good practice to handle unexpected cases.
		return nil, fmt.Errorf("unexpected algorithm: %v", GetTypeByAlgorithm(alg))
	}
}
