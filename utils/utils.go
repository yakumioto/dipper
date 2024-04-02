package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/pbkdf2"

	"github.com/yakumioto/go-crypto-suite/types"
)

type RandomSizeFunc func(len int) ([]byte, error)

var (
	RandomSize RandomSizeFunc = func(len int) ([]byte, error) {
		iv := make([]byte, len)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}

		return iv, nil
	}
)

func ExtendKey(key []byte, keyLen int) []byte {
	return pbkdf2.Key(key, nil, 1, keyLen, sha256.New)
}

func ToKeyBytes(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case []byte:
		if len(key) == 0 {
			return nil, errors.New("empty key bytes")
		}
		return key, nil
	case string:
		if key == "" {
			return nil, errors.New("empty key string")
		}
		return []byte(key), nil
	default:
		return nil, errors.New("key type not supported")
	}
}

func ToString[T types.DataType](b T) string {
	switch b := any(b).(type) {
	case []byte:
		return string(b)
	case string:
		return b
	}

	return ""
}

func ToHexString[T types.DataType](b T) string {
	switch b := any(b).(type) {
	case []byte:
		return hex.EncodeToString(b)
	case string:
		return b
	}

	return ""
}

func ToBytes[T types.DataType](s T) []byte {
	switch b := any(s).(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}

	return nil
}

func Pkcs7Padding[T types.DataType](src T, blockSize int) []byte {
	srcBytes := ToBytes[T](src)
	paddingSize := blockSize - len(srcBytes)%blockSize

	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	paddedData := make([]byte, len(srcBytes)+len(paddingText))
	copy(paddedData, srcBytes)
	copy(paddedData[len(srcBytes):], paddingText)

	return paddedData
}

func Pkcs7UnPadding[T types.DataType](src T) (T, error) {
	srcBytes := ToBytes[T](src)
	if len(srcBytes) == 0 {
		return T(""), errors.New("cannot be empty")
	}

	paddingSize := int(srcBytes[len(srcBytes)-1])
	if paddingSize == 0 || paddingSize > len(srcBytes) {
		return T(""), errors.New("invalid padding size")
	}

	// Check that all padding bytes are correct
	for _, padByte := range srcBytes[len(srcBytes)-paddingSize:] {
		if int(padByte) != paddingSize {
			return T(""), errors.New("invalid padding")
		}
	}

	return T(srcBytes[:len(srcBytes)-paddingSize]), nil
}
