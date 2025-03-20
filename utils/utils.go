package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/pbkdf2"
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

func Pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func Pkcs7UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}

	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}
