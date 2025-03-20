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
	"strings"

	"github.com/yakumioto/dipper/key"
	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

var (
	ErrUnsupportedMethod = errors.New("ecdsa: unsupported method")
)

type PrivateKey struct {
	privateKey *ecdsa.PrivateKey
	algorithm  types.Algorithm
}

func (e *PrivateKey) Algorithm() types.Algorithm {
	return e.algorithm
}

func (e *PrivateKey) Export() ([]byte, error) {
	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pkcs8Encoded}), nil
}

func (e *PrivateKey) SKI() []byte {
	pubKey, _ := e.PublicKey()
	return pubKey.SKI()
}

func (e *PrivateKey) PublicKey() (key.Key, error) {
	return &PublicKey{
		algorithm: e.algorithm,
		publicKey: &e.privateKey.PublicKey,
	}, nil
}

func (e *PrivateKey) Sign(msg []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("ecdsa: failed to write message bytes to hash: %w", err)
	}
	digest := h.Sum(nil)

	payload, err := e.privateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: failed to sign message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(e.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(digest))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return data.Bytes(), nil
}

func (e *PrivateKey) Verify(_, _ []byte) (bool, error) {

	return false, ErrUnsupportedMethod
}

func (e *PrivateKey) Encrypt(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (e *PrivateKey) Decrypt(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

type PublicKey struct {
	publicKey *ecdsa.PublicKey
	algorithm types.Algorithm
}

func (e *PublicKey) Algorithm() types.Algorithm {
	return e.algorithm
}

func (e *PublicKey) Export() ([]byte, error) {
	pkcs8Encoded, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: failed to marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8Encoded}), nil
}

func (e *PublicKey) SKI() []byte {
	raw := elliptic.MarshalCompressed(e.publicKey.Curve, e.publicKey.X, e.publicKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (e *PublicKey) PublicKey() (key.Key, error) {
	return e, ErrUnsupportedMethod
}

func (e *PublicKey) Sign(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (e *PublicKey) Verify(msg, signature []byte) (bool, error) {
	dataBytes := string(signature)

	parts := strings.SplitN(dataBytes, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("ecdsa: invalid signature data structure")
	}

	algorithm, encodedDigest, encodedSignature := parts[0], parts[1], parts[2]

	if algorithm != e.algorithm {
		return false, fmt.Errorf("ecdsa: invalid algorithm type: %s", algorithm)
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
	if _, err = h.Write(msg); err != nil {
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

func (e *PublicKey) Encrypt(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (e *PublicKey) Decrypt(_ []byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

type KeyGeneratorImpl struct{}

func (e *KeyGeneratorImpl) KeyGen(alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	var curve elliptic.Curve
	switch alg {
	case types.EcdsaP256:
		curve = elliptic.P256()
	case types.EcdsaP384:
		curve = elliptic.P384()
	case types.EcdsaP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("ecdsa: invalid algorithm: %v", alg)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: failed to generate private key: %w", err)
	}

	return &PrivateKey{
		algorithm:  alg,
		privateKey: privateKey,
	}, nil
}

type KeyImportImpl struct{}

func (e *KeyImportImpl) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option) (key.Key, error) {
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
		return &PrivateKey{
			algorithm:  alg,
			privateKey: k.(*ecdsa.PrivateKey),
		}, nil
	}

	k, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		return &PublicKey{
			algorithm: alg,
			publicKey: k.(*ecdsa.PublicKey),
		}, nil
	}

	return nil, fmt.Errorf("ecdsa: failed to parse key pkcs8 error: %w, pkix error: %w", pkcs8Err, pkixErr)
}
