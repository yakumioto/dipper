package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

type randomSizeFunc func(len int) ([]byte, error)

var (
	ErrEmptyKey          = errors.New("key cannot be empty")
	ErrUnsupportedKey    = errors.New("unsupported key type, only string or []byte keys are allowed")
	ErrUnsupportedMethod = errors.New("this method is not applicable for the given key type")

	RandomSize randomSizeFunc = func(len int) ([]byte, error) {
		iv := make([]byte, len)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}

		return iv, nil
	}
)

func checkAndConvertKey(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case []byte:
		if len(key) == 0 {
			return nil, ErrEmptyKey
		}
		return key, nil
	case string:
		if key == "" {
			return nil, ErrEmptyKey
		}
		return []byte(key), nil
	default:
		return nil, ErrUnsupportedKey
	}
}

func toString[T DataType](b T) string {
	switch b := any(b).(type) {
	case []byte:
		return string(b)
	case string:
		return b
	}

	return ""
}

func toHexString[T DataType](b T) string {
	switch b := any(b).(type) {
	case []byte:
		return hex.EncodeToString(b)
	case string:
		return b
	}

	return ""
}

func toBytes[T DataType](s T) []byte {
	switch b := any(s).(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}

	return nil
}

func pkcs7Padding[T DataType](src T, blockSize int) []byte {
	srcBytes := toBytes[T](src)
	paddingSize := blockSize - len(srcBytes)%blockSize

	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	paddedData := make([]byte, len(srcBytes)+len(paddingText))
	copy(paddedData, srcBytes)
	copy(paddedData[len(srcBytes):], paddingText)

	return paddedData
}

func pkcs7UnPadding[T DataType](src T) (T, error) {
	srcBytes := toBytes[T](src)
	if len(srcBytes) == 0 {
		return T(""), errors.New("source cannot be empty")
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

func splitN[T DataType](s, sep T, n int) []T {
	switch s := any(s).(type) {
	case string:
		return any(strings.SplitN(s, any(sep).(string), n)).([]T)
	case []byte:
		return any(bytes.SplitN(s, any(sep).([]byte), n)).([]T)
	default:
		panic("Unsupported type")
	}
}
