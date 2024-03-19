package crypto

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
)

type rsaPrivateKeyImpl[T DataType] struct {
	algorithm  Algorithm
	privateKey *rsa.PrivateKey
}

func (r *rsaPrivateKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(r.algorithm)
}

func (r *rsaPrivateKeyImpl[T]) Bytes() (T, error) {
	pkcs1Encoded := x509.MarshalPKCS1PrivateKey(r.privateKey)
	if pkcs1Encoded != nil {
		return T(""), errors.New("failed to marshal private key")
	}

	return T(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs1Encoded,
	})), nil
}

func (r *rsaPrivateKeyImpl[T]) SKI() T {
	pubKey, _ := r.PublicKey()
	return pubKey.SKI()
}

func (r *rsaPrivateKeyImpl[T]) PublicKey() (Key[T], error) {
	return &rsaPublicKeyImpl[T]{
		publicKey: &r.privateKey.PublicKey,
		algorithm: r.algorithm,
	}, nil
}

func (r *rsaPrivateKeyImpl[T]) Sign(msg T) (T, error) {
	digest := sha256.New()
	if _, err := digest.Write(toBytes(msg)); err != nil {
		return T(""), fmt.Errorf("failed to compute message digest: %w", err)
	}

	payload, err := rsa.SignPSS(rand.Reader, r.privateKey, crypto.SHA256, digest.Sum(nil), &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return T(""), fmt.Errorf("failed to sign message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(r.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(digest.Sum(nil)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (r *rsaPrivateKeyImpl[T]) Verify(_, _ T) (bool, error) {
	return false, nil
}

func (r *rsaPrivateKeyImpl[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (r *rsaPrivateKeyImpl[T]) Decrypt(ciphertext T) (T, error) {
	dataBytes := toString(ciphertext)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return T(""), errors.New("invalid ciphertext structure")
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		return T(""), errors.New("type is not a number")
	}

	if Algorithm(typ) != r.algorithm {
		return T(""), fmt.Errorf("algorithm mismatch: %v", GetTypeByAlgorithm(Algorithm(typ)))
	}

	encryptedData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return T(""), errors.New("failed to decode encrypted data")
	}

	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privateKey, encryptedData, nil)
	if err != nil {
		return T(""), fmt.Errorf("decrypt error: %w", err)
	}

	return T(data), nil
}

type rsaPublicKeyImpl[T DataType] struct {
	algorithm Algorithm
	publicKey *rsa.PublicKey
}

func (r *rsaPublicKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(r.algorithm)
}

func (r *rsaPublicKeyImpl[T]) Bytes() (T, error) {
	pkcs1Encoded := x509.MarshalPKCS1PublicKey(r.publicKey)
	return T(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkcs1Encoded,
	})), nil
}

func (r *rsaPublicKeyImpl[T]) SKI() T {
	raw := x509.MarshalPKCS1PublicKey(r.publicKey)
	hash := sha256.Sum256(raw)
	return T(hash[:])
}

func (r *rsaPublicKeyImpl[T]) PublicKey() (Key[T], error) {
	return r, nil
}

func (r *rsaPublicKeyImpl[T]) Sign(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (r *rsaPublicKeyImpl[T]) Verify(msg, signature T) (bool, error) {
	sigStr := toString(signature)

	// Split the signature into parts and validate the structure.
	parts := strings.SplitN(sigStr, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("invalid signature structure")
	}

	// Verify the algorithm type.
	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, errors.New("type is not a number")
	}

	if Algorithm(typ) != r.algorithm {
		return false, fmt.Errorf("algorithm mismatch: %v", GetTypeByAlgorithm(Algorithm(typ)))
	}

	// Decode the provided digest and payload.
	providedDigest, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, errors.New("failed to decode provided digest")
	}

	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, errors.New("failed to decode payload")
	}

	// Compute the digest of the message.
	digest := sha256.New()
	if _, err = digest.Write(toBytes[T](msg)); err != nil {
		return false, fmt.Errorf("failed to compute message digest: %w", err)
	}

	computedDigest := digest.Sum(nil)

	// Verify that the computed digest matches the provided digest.
	if !bytes.Equal(computedDigest, providedDigest) {
		return false, errors.New("digest mismatch")
	}

	// Verify the signature using RSA-PSS.
	err = rsa.VerifyPSS(r.publicKey, crypto.SHA256, computedDigest, payload, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})

	return err == nil, err
}

func (r *rsaPublicKeyImpl[T]) Encrypt(plaintext T) (T, error) {
	payload, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.publicKey, toBytes(plaintext), nil)
	if err != nil {
		return T(""), fmt.Errorf("encrypt error: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(r.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (r *rsaPublicKeyImpl[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type rsaKeyGeneratorImpl[T DataType] struct{}

func (r *rsaKeyGeneratorImpl[T]) KeyGen(alg Algorithm) (Key[T], error) {
	var bits int

	switch alg {
	case Rsa1024:
		bits = 1024
	case Rsa2048:
		bits = 2048
	case Rsa4096:
		bits = 4096
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm: %v", GetTypeByAlgorithm(alg))
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key for [%v] error: [%w]", bits, err)
	}

	return &rsaPrivateKeyImpl[T]{
		algorithm:  alg,
		privateKey: privateKey,
	}, nil
}

type rsaKeyImportImpl[T DataType] struct{}

func (r *rsaKeyImportImpl[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
	data, err := checkAndConvertKey(raw)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return &rsaPrivateKeyImpl[T]{
			algorithm:  alg,
			privateKey: privateKey,
		}, nil
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return &rsaPublicKeyImpl[T]{
			algorithm: alg,
			publicKey: publicKey,
		}, nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %v", GetTypeByAlgorithm(alg))
}
