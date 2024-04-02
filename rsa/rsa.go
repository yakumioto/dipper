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
	"strconv"
	"strings"

	"github.com/yakumioto/go-crypto-suite/key"
	"github.com/yakumioto/go-crypto-suite/types"
	"github.com/yakumioto/go-crypto-suite/utils"
)

var (
	ErrUnsupportedMethod = errors.New("rsa: unsupported method")
)

type PrivateKeyImpl[T types.DataType] struct {
	algorithm  types.Algorithm
	privateKey *rsa.PrivateKey
}

func (r *PrivateKeyImpl[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(r.algorithm)
}

func (r *PrivateKeyImpl[T]) Bytes() (T, error) {
	pkcs1Encoded := x509.MarshalPKCS1PrivateKey(r.privateKey)
	if pkcs1Encoded == nil {
		return T(""), errors.New("rsa: failed to marshal private key")
	}

	return T(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE RSA KEY",
		Bytes: pkcs1Encoded,
	})), nil
}

func (r *PrivateKeyImpl[T]) SKI() T {
	pubKey, _ := r.PublicKey()
	return pubKey.SKI()
}

func (r *PrivateKeyImpl[T]) PublicKey() (key.Key[T], error) {
	return &PublicKeyImpl[T]{
		publicKey: &r.privateKey.PublicKey,
		algorithm: r.algorithm,
	}, nil
}

func (r *PrivateKeyImpl[T]) Sign(msg T) (T, error) {
	h := sha256.New()
	if _, err := h.Write(utils.ToBytes(msg)); err != nil {
		return T(""), fmt.Errorf("rsa: failed to write message bytes to hash: %w", err)
	}

	digest := h.Sum(nil)

	payload, err := rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return T(""), fmt.Errorf("rsa: failed to sign message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(r.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(digest))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (r *PrivateKeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, nil
}

func (r *PrivateKeyImpl[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (r *PrivateKeyImpl[T]) Decrypt(ciphertext T) (T, error) {
	dataBytes := utils.ToString(ciphertext)
	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("rsa: invalid encrypted data structure")
	}

	algorithmType, payload := parts[0], parts[1]

	algorithm, err := strconv.Atoi(algorithmType)
	if err != nil {
		return T(""), errors.New("rsa: algorithm type is not a number")
	}

	if algorithm != r.algorithm {
		return T(""), fmt.Errorf("rsa: invalid algorithm type: %s", types.GetTypeByAlgorithm(algorithm))
	}

	encryptedData, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return T(""), fmt.Errorf("rsa: decrypt failed to decode base64: %w", err)
	}

	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privateKey, encryptedData, nil)
	if err != nil {
		return T(""), fmt.Errorf("rsa: decrypt error: %w", err)
	}

	return T(data), nil
}

type PublicKeyImpl[T types.DataType] struct {
	algorithm types.Algorithm
	publicKey *rsa.PublicKey
}

func (r *PublicKeyImpl[T]) AlgorithmType() types.AlgorithmType {
	return types.GetTypeByAlgorithm(r.algorithm)
}

func (r *PublicKeyImpl[T]) Bytes() (T, error) {
	pkcs1Encoded := x509.MarshalPKCS1PublicKey(r.publicKey)
	return T(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkcs1Encoded,
	})), nil
}

func (r *PublicKeyImpl[T]) SKI() T {
	raw := x509.MarshalPKCS1PublicKey(r.publicKey)
	hash := sha256.Sum256(raw)
	return T(hash[:])
}

func (r *PublicKeyImpl[T]) PublicKey() (key.Key[T], error) {
	return r, nil
}

func (r *PublicKeyImpl[T]) Sign(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (r *PublicKeyImpl[T]) Verify(msg, signature T) (bool, error) {
	dataBytes := utils.ToString(signature)

	parts := strings.SplitN(dataBytes, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("rsa: invalid signature data structure")
	}

	algorithmType, encodedDigest, encodedSignature := parts[0], parts[1], parts[2]

	algorithm, err := strconv.Atoi(algorithmType)
	if err != nil {
		return false, errors.New("rsa: algorithm type is not a number")
	}

	if algorithm != r.algorithm {
		return false, fmt.Errorf("rsa: invalid algorithm type: %s", types.GetTypeByAlgorithm(algorithm))
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
	if _, err = h.Write(utils.ToBytes(msg)); err != nil {
		return false, fmt.Errorf("rsa: failed to compute message : %w", err)
	}
	digest := h.Sum(nil)

	if !bytes.Equal(digest, providedDigest) {
		return false, fmt.Errorf("rsa: invalid digest")
	}

	if err = rsa.VerifyPSS(r.publicKey, crypto.SHA256, digest, providedSignature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}); err != nil {
		return false, fmt.Errorf("rsa: failed to verify signature: %w", err)
	}

	return true, nil
}

func (r *PublicKeyImpl[T]) Encrypt(plaintext T) (T, error) {
	payload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.publicKey, utils.ToBytes(plaintext), nil)
	if err != nil {
		return T(""), fmt.Errorf("rsa: failed to encrypt message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(r.algorithm))
	data.WriteString(".")
	data.WriteString(base64.RawStdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (r *PublicKeyImpl[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type KeyGeneratorImpl[T types.DataType] struct{}

func (r *KeyGeneratorImpl[T]) KeyGen(alg types.Algorithm) (key.Key[T], error) {
	var bits int

	switch alg {
	case types.Rsa1024:
		bits = 1024
	case types.Rsa2048:
		bits = 2048
	case types.Rsa4096:
		bits = 4096
	default:
		return nil, fmt.Errorf("rsa: invalid algorithm: %v", types.GetTypeByAlgorithm(alg))
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa: failed to generate private key: %w", err)
	}

	return &PrivateKeyImpl[T]{
		algorithm:  alg,
		privateKey: privateKey,
	}, nil
}

type KeyImportImpl[T types.DataType] struct{}

func (r *KeyImportImpl[T]) KeyImport(raw interface{}, alg types.Algorithm) (key.Key[T], error) {
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
		return &PrivateKeyImpl[T]{
			algorithm:  alg,
			privateKey: privKey,
		}, nil
	}

	pubKey, pubErr := x509.ParsePKCS1PublicKey(block.Bytes)
	if pubErr == nil {
		return &PublicKeyImpl[T]{
			algorithm: alg,
			publicKey: pubKey,
		}, nil
	}

	return nil, fmt.Errorf("rsa: failed to parse private key error: %w, public key error: %w", privErr, pubErr)
}
