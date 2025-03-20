package utils

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToKeyBytes(t *testing.T) {
	testCases := []struct {
		name        string
		input       interface{}
		expected    []byte
		expectError bool
	}{
		{
			name:        "空字符串键",
			input:       "",
			expectError: true,
		},
		{
			name:        "空字节数组键",
			input:       []byte{},
			expectError: true,
		},
		{
			name:        "不支持的结构体类型",
			input:       struct{}{},
			expectError: true,
		},
		{
			name:        "有效字符串键",
			input:       "validKey",
			expected:    []byte("validKey"),
			expectError: false,
		},
		{
			name:        "有效字节数组键",
			input:       []byte("validBytes"),
			expected:    []byte("validBytes"),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ToKeyBytes(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestExtendKey(t *testing.T) {
	testCases := []struct {
		name           string
		inputKey       []byte
		targetLength   int
		expectedLength int
	}{
		{
			name:           "短密钥扩展到16字节",
			inputKey:       []byte("short"),
			targetLength:   16,
			expectedLength: 16,
		},
		{
			name:           "长密钥扩展到32字节",
			inputKey:       []byte("this is a longer key for testing"),
			targetLength:   32,
			expectedLength: 32,
		},
		{
			name:           "扩展到0长度",
			inputKey:       []byte("short"),
			targetLength:   0,
			expectedLength: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtendKey(tc.inputKey, tc.targetLength)
			assert.Equal(t, tc.expectedLength, len(result))
		})
	}
}

func TestRandomSize(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{
			name:   "生成8字节随机数据",
			length: 8,
		},
		{
			name:   "生成16字节随机数据",
			length: 16,
		},
		{
			name:   "生成32字节随机数据",
			length: 32,
		},
		{
			name:   "生成64字节随机数据",
			length: 64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			randomBytes, err := RandomSize(tc.length)
			assert.NoError(t, err)
			assert.Equal(t, tc.length, len(randomBytes))

			// 生成另一组随机数据确保它们不同（随机性检查）
			anotherRandomBytes, err := RandomSize(tc.length)
			assert.NoError(t, err)
			assert.Equal(t, tc.length, len(anotherRandomBytes))

			// 两组随机数据极不可能相同
			assert.NotEqual(t, randomBytes, anotherRandomBytes)
		})
	}
}

func TestPkcs7Padding(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		blockSize int
		expected  []byte
	}{
		{
			name:      "数据长度小于块大小的填充",
			input:     []byte("hello world"),
			blockSize: 16,
			expected:  []byte("hello world\x05\x05\x05\x05\x05"),
		},
		{
			name:      "数据长度接近块大小的填充",
			input:     []byte("exactly sixteen"),
			blockSize: 16,
			expected:  append([]byte("exactly sixteen"), byte(1)),
		},
		{
			name:      "空字节数组的填充",
			input:     []byte{},
			blockSize: 8,
			expected:  bytes.Repeat([]byte{byte(8)}, 8),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := Pkcs7Padding(tc.input, tc.blockSize)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPkcs7UnPadding(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "解除已填充数组的填充",
			input:    []byte("hello world\x05\x05\x05\x05\x05"),
			expected: []byte("hello world"),
		},
		{
			name:     "解除填充为整块的数据",
			input:    append([]byte("sixteen bytes..."), bytes.Repeat([]byte{byte(16)}, 16)...),
			expected: []byte("sixteen bytes..."),
		},
		{
			name:     "解除空字节数组的填充",
			input:    []byte{},
			expected: []byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := Pkcs7UnPadding(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
