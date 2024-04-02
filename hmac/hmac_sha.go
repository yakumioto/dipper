package hmac

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"sync"

	"github.com/yakumioto/go-crypto-suite/key"
	"github.com/yakumioto/go-crypto-suite/types"
	"github.com/yakumioto/go-crypto-suite/utils"
)

var (
	ErrUnsupportedMethod = errors.New("hmac-sha: unsupported method")
)

type ShaKeyImpl[T types.DataType] struct {
	key       []byte
	h         hash.Hash
	mux       sync.Mutex
	algorithm types.Algorithm
}

func (h *ShaKeyImpl[T]) sum(msg []byte) []byte {
	h.mux.Lock()
	defer h.h.Reset()
	defer h.mux.Unlock()

	h.h.Write(msg)
	return h.h.Sum(nil)
}

func (h *ShaKeyImpl[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(h.algorithm)
}

func (h *ShaKeyImpl[T]) Bytes() (T, error) {
	return T(h.key), nil
}

func (h *ShaKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(h.key)

	return T(utils.ToHexString(sha.Sum(nil)))
}

func (h *ShaKeyImpl[T]) PublicKey() (key.Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (h *ShaKeyImpl[T]) Sign(msg T) (signature T, err error) {
	h2 := sha256.New()
	if _, err := h2.Write(utils.ToBytes(msg)); err != nil {
		return T(""), fmt.Errorf("hmac-sha: failed to write message bytes to hash: %w", err)
	}

	digest := h2.Sum(nil)

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(h.algorithm))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(digest))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(h.sum(digest)))

	return T(data.Bytes()), nil
}

func (h *ShaKeyImpl[T]) Verify(msg, signature T) (bool, error) {
	dataBytes := utils.ToString(signature)

	parts := strings.SplitN(dataBytes, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("hmac-sha: invalid signature data structure")
	}

	algorithmType, encodedDigest, encodedSignature := parts[0], parts[1], parts[2]

	algorithm, err := strconv.Atoi(algorithmType)
	if err != nil {
		return false, errors.New("hmac-sha: algorithm type is not a number")
	}

	if algorithm != h.algorithm {
		return false, fmt.Errorf("hmac-sha: invalid algorithm type: %s", types.GetTypeByAlgorithm(algorithm))
	}

	providedDigest, err := base64.RawStdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return false, fmt.Errorf("hmac-sha: decrypt provided digest failed to decode base64: %w", err)
	}

	providedSignature, err := base64.RawStdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false, fmt.Errorf("hmac-sha: decrypt provided signature failed to decode base64: %w", err)
	}

	h2 := sha256.New()
	if _, err = h2.Write(utils.ToBytes(msg)); err != nil {
		return false, fmt.Errorf("hmac-sha: failed to compute message : %w", err)
	}

	digest := h2.Sum(nil)

	if subtle.ConstantTimeCompare(digest, providedDigest) == 0 {
		return false, fmt.Errorf("hmac-sha: invalid digest")
	}

	return subtle.ConstantTimeCompare(h.sum(digest), providedSignature) == 1, nil
}

func (h *ShaKeyImpl[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (h *ShaKeyImpl[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type ShaKeyImportImpl[T types.DataType] struct{}

func (h *ShaKeyImportImpl[T]) KeyImport(raw interface{}, alg types.Algorithm) (key.Key[T], error) {
	key, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, err
	}

	switch alg {
	case types.HmacSha256:
		return &ShaKeyImpl[T]{
			key:       key,
			h:         sha256.New(),
			algorithm: alg,
		}, nil
	case types.HmacSha512:
		return &ShaKeyImpl[T]{
			key:       key,
			h:         sha512.New(),
			algorithm: alg,
		}, nil
	default:
		return nil, fmt.Errorf("hmac-sha: unsupported algorithm: %v", types.GetTypeByAlgorithm(alg))
	}
}