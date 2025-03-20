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

type ShaKeyImpl struct {
	key           []byte
	algorithm     types.Algorithm
	signatureFunc func() hash.Hash
}

func (s *ShaKeyImpl) Algorithm() types.Algorithm {
	return s.algorithm
}

func (s *ShaKeyImpl) Export() ([]byte, error) {
	return s.key, nil
}

func (s *ShaKeyImpl) SKI() []byte {
	sha := sha256.New()
	sha.Write(s.key)
	return sha.Sum(nil)
}

func (s *ShaKeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (s *ShaKeyImpl) Sign(msg []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("hmac-sha: failed to write message bytes to hash: %w", err)
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

	return data.Bytes(), nil
}

func (s *ShaKeyImpl) Verify(msg, signature []byte) (bool, error) {
	dataStr := string(signature)
	parts := strings.SplitN(dataStr, ".", 3)
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
	if _, err = h.Write(msg); err != nil {
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

func (s *ShaKeyImpl) Encrypt([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (s *ShaKeyImpl) Decrypt([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

type ShaKeyImportImpl struct{}

func (h *ShaKeyImportImpl) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	keyBytes, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, err
	}

	switch alg {
	case types.HmacSha256:
		return &ShaKeyImpl{
			key:           keyBytes,
			algorithm:     alg,
			signatureFunc: sha256.New,
		}, nil
	case types.HmacSha512:
		return &ShaKeyImpl{
			key:           keyBytes,
			algorithm:     alg,
			signatureFunc: sha512.New,
		}, nil
	default:
		return nil, fmt.Errorf("hmac-sha: unsupported algorithm: %v", alg)
	}
}
