package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/pbkdf2"

	"github.com/yakumioto/dipper/types"
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
	dataBytes := ToBytes(b)

	return hex.EncodeToString(dataBytes)
}

func ToBytes[T types.DataType](s T) []byte {
	switch b := any(s).(type) {
	case string:
		return []byte(b)
	default:
		return b.([]byte)
	}
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

func Pkcs7UnPadding[T types.DataType](src T) T {
	srcBytes := ToBytes[T](src)
	length := len(srcBytes)
	if length == 0 {
		return src
	}

	unPadding := int(srcBytes[length-1])
	return T(srcBytes[:(length - unPadding)])
}
