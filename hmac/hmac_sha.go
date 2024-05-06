package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

var (
	ErrUnsupportedMethod = errors.New("hmac-sha: unsupported method")
)

type ShaKeyImpl[T types.DataType] struct {
	key           []byte
	algorithm     types.Algorithm
	signatureFunc func() hash.Hash
}

func (s *ShaKeyImpl[T]) Algorithm() types.Algorithm {
	return s.algorithm
}

func (s *ShaKeyImpl[T]) Export() (T, error) {
	return T(s.key), nil
}

func (s *ShaKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(s.key)

	return T(utils.ToHexString(sha.Sum(nil)))
}

func (s *ShaKeyImpl[T]) PublicKey() (key.Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (s *ShaKeyImpl[T]) Sign(msg T) (signature T, err error) {
	h := sha256.New()
	if _, err := h.Write(utils.ToBytes(msg)); err != nil {
		return T(""), fmt.Errorf("hmac-sha: failed to write message bytes to hash: %w", err)
	}

	digest := h.Sum(nil)

	hc := hmac.New(s.signatureFunc, s.key)
	hc.Write(digest)

	data := bytes.NewBuffer(nil)
	data.WriteString(s.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(digest))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(hc.Sum(nil)))

	return T(data.Bytes()), nil
}

func (s *ShaKeyImpl[T]) Verify(msg, signature T) (bool, error) {
	dataBytes := utils.ToString(signature)

	parts := strings.SplitN(dataBytes, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("hmac-sha: invalid signature data structure")
	}

	algorithm, encodedDigest, encodedSignature := parts[0], parts[1], parts[2]

	if algorithm != s.algorithm {
		return false, fmt.Errorf("hmac-sha: invalid algorithm type: %s", algorithm)
	}

	providedDigest, err := base64.RawStdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return false, fmt.Errorf("hmac-sha: decrypt provided digest failed to decode base64: %w", err)
	}

	providedSignature, err := base64.RawStdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false, fmt.Errorf("hmac-sha: decrypt provided signature failed to decode base64: %w", err)
	}

	h := sha256.New()
	if _, err = h.Write(utils.ToBytes(msg)); err != nil {
		return false, fmt.Errorf("hmac-sha: failed to compute message : %w", err)
	}

	digest := h.Sum(nil)

	hc := hmac.New(s.signatureFunc, s.key)
	hc.Write(digest)

	if !bytes.Equal(digest, providedDigest) {
		return false, fmt.Errorf("hmac-sha: invalid digest")
	}

	return hmac.Equal(hc.Sum(nil), providedSignature), nil
}

func (s *ShaKeyImpl[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (s *ShaKeyImpl[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type ShaKeyImportImpl[T types.DataType] struct{}

func (h *ShaKeyImportImpl[T]) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option[T]) (key.Key[T], error) {
	keyBytes, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, err
	}

	switch alg {
	case types.HmacSha256:
		return &ShaKeyImpl[T]{
			key:           keyBytes,
			algorithm:     alg,
			signatureFunc: sha256.New,
		}, nil
	case types.HmacSha512:
		return &ShaKeyImpl[T]{
			key:           keyBytes,
			algorithm:     alg,
			signatureFunc: sha512.New,
		}, nil
	default:
		return nil, fmt.Errorf("hmac-sha: unsupported algorithm: %v", alg)
	}
}
