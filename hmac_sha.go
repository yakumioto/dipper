package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
)

type hmacShaKeyImpl[T DataType] struct {
	key       []byte
	algorithm Algorithm
}

func (h *hmacShaKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(h.algorithm)
}

func (h *hmacShaKeyImpl[T]) Bytes() (T, error) {
	return T(toHexString(h.key)), nil
}

func (h *hmacShaKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(h.key)

	return T(toHexString(sha.Sum(nil)))
}

func (h *hmacShaKeyImpl[T]) PublicKey() (Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (h *hmacShaKeyImpl[T]) Sign(msg T) (signature T, err error) {
	var hc hash.Hash
	// Determine the algorithm type and create a new HMAC hash.
	switch h.algorithm {
	case HmacSha256:
		hc = hmac.New(sha256.New, h.key)
	case HmacSha512:
		hc = hmac.New(sha512.New, h.key)
	default:
		err = fmt.Errorf("not support %v algorithm", GetTypeByAlgorithm(h.algorithm))
		return
	}

	hc.Write(toBytes(msg))
	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(h.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(hc.Sum(nil)))

	return T(data.Bytes()), nil
}

func (h *hmacShaKeyImpl[T]) Verify(msg, signature T) (bool, error) {
	reSignature, err := h.Sign(msg)
	if err != nil {
		return false, err
	}

	return bytes.Equal(toBytes(reSignature), toBytes(signature)), err
}

func (h *hmacShaKeyImpl[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (h *hmacShaKeyImpl[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type hmacShaKeyImportImpl[T DataType] struct{}

func (h *hmacShaKeyImportImpl[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
	key, err := checkAndConvertKey(raw)
	if err != nil {
		return nil, err
	}

	switch alg {
	case HmacSha256, HmacSha512:
		return &hmacShaKeyImpl[T]{
			key:       key,
			algorithm: alg,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", GetTypeByAlgorithm(alg))
	}
}
