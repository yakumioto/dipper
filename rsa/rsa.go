package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	ErrUnsupportedMethod = errors.New("rsa: unsupported method")
)

type PrivateKeyImpl struct {
	algorithm  types.Algorithm
	privateKey *rsa.PrivateKey
}

func (r *PrivateKeyImpl) Algorithm() types.Algorithm {
	return r.algorithm
}

func (r *PrivateKeyImpl) Export() ([]byte, error) {
	pkcs1Encoded := x509.MarshalPKCS1PrivateKey(r.privateKey)
	if pkcs1Encoded == nil {
		return nil, errors.New("rsa: failed to marshal private key")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE RSA KEY",
		Bytes: pkcs1Encoded,
	}), nil
}

func (r *PrivateKeyImpl) SKI() []byte {
	pubKey, _ := r.PublicKey()
	return pubKey.SKI()
}

func (r *PrivateKeyImpl) PublicKey() (key.Key, error) {
	return &PublicKeyImpl{
		publicKey: &r.privateKey.PublicKey,
		algorithm: r.algorithm,
	}, nil
}

func (r *PrivateKeyImpl) Sign(msg []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("rsa: failed to write message bytes to hash: %w", err)
	}

	digest := h.Sum(nil)

	payload, err := rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return nil, fmt.Errorf("rsa: failed to sign message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(r.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(digest))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return data.Bytes(), nil
}

func (r *PrivateKeyImpl) Verify(_, _ []byte) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (r *PrivateKeyImpl) Encrypt([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (r *PrivateKeyImpl) Decrypt(ciphertext []byte) ([]byte, error) {
	dataStr := string(ciphertext)
	parts := strings.SplitN(dataStr, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("rsa: invalid encrypted data structure")
	}

	algorithm, payload := parts[0], parts[1]

	if algorithm != r.algorithm {
		return nil, fmt.Errorf("rsa: invalid algorithm type: %s", algorithm)
	}

	encryptedData, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("rsa: decrypt failed to decode base64: %w", err)
	}

	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privateKey, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa: decrypt error: %w", err)
	}

	return data, nil
}

type PublicKeyImpl struct {
	algorithm types.Algorithm
	publicKey *rsa.PublicKey
}

func (r *PublicKeyImpl) Algorithm() types.Algorithm {
	return r.algorithm
}

func (r *PublicKeyImpl) Export() ([]byte, error) {
	pkcs1Encoded := x509.MarshalPKCS1PublicKey(r.publicKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkcs1Encoded,
	}), nil
}

func (r *PublicKeyImpl) SKI() []byte {
	raw := x509.MarshalPKCS1PublicKey(r.publicKey)
	h := sha256.New()
	h.Write(raw)
	return h.Sum(nil)
}

func (r *PublicKeyImpl) PublicKey() (key.Key, error) {
	return nil, ErrUnsupportedMethod
}

func (r *PublicKeyImpl) Sign([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

func (r *PublicKeyImpl) Verify(msg, signature []byte) (bool, error) {
	dataStr := string(signature)
	parts := strings.SplitN(dataStr, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("rsa: invalid signature data structure")
	}

	algorithm, encodedDigest, encodedSignature := parts[0], parts[1], parts[2]

	if algorithm != r.algorithm {
		return false, fmt.Errorf("rsa: invalid algorithm type: %s", algorithm)
	}

	providedDigest, err := base64.RawStdEncoding.DecodeString(encodedDigest)
	if err != nil {
		return false, fmt.Errorf("rsa: decrypt provided digest failed to decode base64: %w", err)
	}

	providedSignature, err := base64.RawStdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return false, fmt.Errorf("rsa: decrypt provided signature failed to decode base64: %w", err)
	}

	h := sha256.New()
	if _, err = h.Write(msg); err != nil {
		return false, fmt.Errorf("rsa: failed to compute message : %w", err)
	}
	digest := h.Sum(nil)

	if !bytes.Equal(digest, providedDigest) {
		return false, fmt.Errorf("rsa: invalid digest")
	}

	if err = rsa.VerifyPSS(r.publicKey, crypto.SHA256, digest, providedSignature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}); err != nil {
		return false, nil
	}

	return true, nil
}

func (r *PublicKeyImpl) Encrypt(plaintext []byte) ([]byte, error) {
	payload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.publicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa: failed to encrypt message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(r.algorithm)
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return data.Bytes(), nil
}

func (r *PublicKeyImpl) Decrypt([]byte) ([]byte, error) {
	return nil, ErrUnsupportedMethod
}

type KeyGeneratorImpl struct{}

func (r *KeyGeneratorImpl) KeyGen(alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	var bits int

	switch alg {
	case types.Rsa1024:
		bits = 1024
	case types.Rsa2048:
		bits = 2048
	case types.Rsa4096:
		bits = 4096
	default:
		return nil, fmt.Errorf("rsa: invalid algorithm: %v", alg)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa: failed to generate private key: %w", err)
	}

	return &PrivateKeyImpl{
		algorithm:  alg,
		privateKey: privateKey,
	}, nil
}

type KeyImportImpl struct{}

func (r *KeyImportImpl) KeyImport(raw interface{}, alg types.Algorithm, opts ...key.Option) (key.Key, error) {
	data, err := utils.ToKeyBytes(raw)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("rsa: failed to decode pem block")
	}

	privKey, privErr := x509.ParsePKCS1PrivateKey(block.Bytes)
	if privErr == nil {
		return &PrivateKeyImpl{
			algorithm:  alg,
			privateKey: privKey,
		}, nil
	}

	pubKey, pubErr := x509.ParsePKCS1PublicKey(block.Bytes)
	if pubErr == nil {
		return &PublicKeyImpl{
			algorithm: alg,
			publicKey: pubKey,
		}, nil
	}

	return nil, fmt.Errorf("rsa: failed to parse private key error: %w, public key error: %w", privErr, pubErr)
}
