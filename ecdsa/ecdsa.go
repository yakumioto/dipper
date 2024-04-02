package ecdsa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/yakumioto/go-crypto-suite/key"
	"github.com/yakumioto/go-crypto-suite/types"
	"github.com/yakumioto/go-crypto-suite/utils"
)

var (
	ErrUnsupportedMethod = errors.New("ecdsa: unsupported method")
)

type PrivateKey[T types.DataType] struct {
	privateKey *ecdsa.PrivateKey
	algorithm  types.Algorithm
}

func (e *PrivateKey[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(e.algorithm)
}

func (e *PrivateKey[T]) Bytes() (key T, err error) {
	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return T(""), fmt.Errorf("ecdsa: failed to marshal private pubKey: %w", err)
	}

	return T(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkcs8Encoded})), nil
}

func (e *PrivateKey[T]) SKI() T {
	pubKey, _ := e.PublicKey()
	return pubKey.SKI()
}

func (e *PrivateKey[T]) PublicKey() (key.Key[T], error) {
	return &PublicKey[T]{
		algorithm: e.algorithm,
		publicKey: &e.privateKey.PublicKey}, nil
}

func (e *PrivateKey[T]) Sign(msg T) (signature T, err error) {
	h := sha256.New()
	if _, err = h.Write(utils.ToBytes(msg)); err != nil {
		return T(""), fmt.Errorf("ecdsa: failed to write message bytes to hash: %w", err)
	}
	digest := h.Sum(nil)

	payload, err := e.privateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return T(""), fmt.Errorf("ecdsa: failed to sign message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(e.algorithm))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(digest))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (e *PrivateKey[T]) Verify(_, _ T) (bool, error) {

	return false, ErrUnsupportedMethod
}

func (e *PrivateKey[T]) Encrypt(_ T) (ciphertext T, err error) {
	return T(""), ErrUnsupportedMethod
}

func (e *PrivateKey[T]) Decrypt(_ T) (plaintext T, err error) {
	return T(""), ErrUnsupportedMethod
}

type PublicKey[T types.DataType] struct {
	publicKey *ecdsa.PublicKey
	algorithm types.Algorithm
}

func (e *PublicKey[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(e.algorithm)
}

func (e *PublicKey[T]) Bytes() (key T, err error) {
	pkcs8Encoded, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		return T(""), fmt.Errorf("ecdsa: failed to marshal public pubKey: %w", err)
	}
	return T(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8Encoded})), nil
}

func (e *PublicKey[T]) SKI() T {
	raw := elliptic.MarshalCompressed(e.publicKey.Curve, e.publicKey.X, e.publicKey.Y)

	hash := sha256.New()
	hash.Write(raw)
	return T(hash.Sum(nil))
}

func (e *PublicKey[T]) PublicKey() (key.Key[T], error) {
	return e, nil
}

func (e *PublicKey[T]) Sign(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (e *PublicKey[T]) Verify(msg, signature T) (bool, error) {
	dataBytes := utils.ToString(signature)

	parts := strings.SplitN(dataBytes, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("ecdsa: invalid signature data structure")
	}

	algorithmType, encodedDigest, encodedSignature := parts[0], parts[1], parts[2]

	algorithm, err := strconv.Atoi(algorithmType)
	if err != nil {
		return false, errors.New("ecdsa: algorithm type is not a number")
	}

	if algorithm != e.algorithm {
		return false, fmt.Errorf("ecdsa: invalid algorithm type: %s", types.GetTypeByAlgorithm(algorithm))
	}

	providedDigest, err := base64.RawStdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return false, fmt.Errorf("ecdsa: decrypt provided digest failed to decode base64: %w", err)
	}

	providedSignature, err := base64.RawStdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false, fmt.Errorf("ecdsa: decrypt provided signature failed to decode base64: %w", err)
	}

	h := sha256.New()
	if _, err = h.Write(utils.ToBytes(msg)); err != nil {
		return false, fmt.Errorf("ecdsa: failed to compute message : %w", err)
	}
	digest := h.Sum(nil)

	if subtle.ConstantTimeCompare(digest, providedDigest) == 0 {
		return false, fmt.Errorf("ecdsa: invalid digest")
	}

	if !ecdsa.VerifyASN1(e.publicKey, digest, providedSignature) {
		return false, nil
	}

	return true, nil
}

func (e *PublicKey[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (e *PublicKey[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type KeyGeneratorImpl[T types.DataType] struct{}

func (e *KeyGeneratorImpl[T]) KeyGen(alg types.Algorithm) (key.Key[T], error) {
	var curve elliptic.Curve
	switch alg {
	case types.EcdsaP256:
		curve = elliptic.P256()
	case types.EcdsaP384:
		curve = elliptic.P384()
	case types.EcdsaP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("ecdsa: invalid algorithm: %v", types.GetTypeByAlgorithm(alg))
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: failed to generate private key: %w", err)
	}

	return &PrivateKey[T]{
		algorithm:  alg,
		privateKey: privateKey,
	}, nil
}

type KeyImportImpl[T types.DataType] struct{}

func (e *KeyImportImpl[T]) KeyImport(raw interface{}, alg types.Algorithm) (key.Key[T], error) {
	keyBytes, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("ecdsa: failed to decode pem block")
	}

	k, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		return &PrivateKey[T]{
			algorithm:  alg,
			privateKey: k.(*ecdsa.PrivateKey),
		}, nil
	}

	k, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		return &PublicKey[T]{
			algorithm: alg,
			publicKey: k.(*ecdsa.PublicKey),
		}, nil
	}

	return nil, fmt.Errorf("ecdsa: failed to parse key pkcs8 error: %w, pkix error: %w", pkcs8Err, pkixErr)
}
