package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToKeyBytes(t *testing.T) {
	// test empty key by string
	_, err := ToKeyBytes("")
	assert.Error(t, err)

	// test empty key by byte
	_, err = ToKeyBytes([]byte{})
	assert.Error(t, err)

	// test key by struct
	_, err = ToKeyBytes(struct{}{})
	assert.Error(t, err)
}

func TestToString(t *testing.T) {
	// test empty key by string
	data := ToString[string]("hello world")
	assert.Equal(t, "hello world", data)

	// test empty key by byte
	data = ToString[[]byte]([]byte("hello world"))
	assert.Equal(t, "hello world", data)
}

func TestToHexString(t *testing.T) {
	data := ToHexString[string]("hello world")
	assert.Equal(t, "68656c6c6f20776f726c64", data)

	data = ToHexString[[]byte]([]byte("hello world"))
	assert.Equal(t, "68656c6c6f20776f726c64", data)

	data = ToHexString[[]byte](nil)
	assert.Equal(t, "", data)
}

func TestToBytes(t *testing.T) {
	// test empty key by string
	data := ToBytes[string]("hello world")
	assert.Equal(t, []byte("hello world"), data)

	// test empty key by byte
	data = ToBytes[[]byte]([]byte("hello world"))
	assert.Equal(t, []byte("hello world"), data)
}

func TestPkcs7Padding(t *testing.T) {
	// Test case 1: Padding a string
	src := "hello world"
	blockSize := 16
	expected := []byte("hello world\x05\x05\x05\x05\x05")
	result := Pkcs7Padding(src, blockSize)
	assert.Equal(t, expected, result)

	// Test case 2: Padding a byte slice
	src2 := []byte("test data")
	blockSize2 := 8
	expected2 := []byte("test data\x07\x07\x07\x07\x07\x07\x07")
	result2 := Pkcs7Padding(src2, blockSize2)
	assert.Equal(t, expected2, result2)

	// Test case 3: Padding an empty string
	src3 := ""
	blockSize3 := 8
	expected3 := []byte("\x08\x08\x08\x08\x08\x08\x08\x08")
	result3 := Pkcs7Padding(src3, blockSize3)
	assert.Equal(t, expected3, result3)
}

func TestPkcs7UnPadding(t *testing.T) {
	// Test case 1: Unpadding a string
	src := []byte("hello world\x05\x05\x05\x05\x05")
	expected := []byte("hello world")
	result := Pkcs7UnPadding(src)
	assert.Equal(t, expected, result)

	// Test case 2: Unpadding a byte slice
	src2 := []byte("test data\x07\x07\x07\x07\x07\x07\x07")
	expected2 := []byte("test data")
	result2 := Pkcs7UnPadding(src2)
	assert.Equal(t, expected2, result2)

	// Test case 3: Unpadding an empty string
	src3 := []byte("\x08\x08\x08\x08\x08\x08\x08\x08")
	expected3 := []byte("")
	result3 := Pkcs7UnPadding(src3)
	assert.Equal(t, expected3, result3)

	// Test case 4: empty byte slice
	src4 := []byte{}
	expected4 := []byte{}
	result4 := Pkcs7UnPadding(src4)
	assert.Equal(t, expected4, result4)
}
