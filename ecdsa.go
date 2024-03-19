package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type ecdsaPrivateKey[T DataType] struct {
	privateKey *ecdsa.PrivateKey
	algorithm  Algorithm
}

func (e *ecdsaPrivateKey[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(e.algorithm)
}

func (e *ecdsaPrivateKey[T]) Bytes() (key T, err error) {
	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return T(""), fmt.Errorf("failed to marshal private key: %w", err)
	}

	return T(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})), nil
}

func (e *ecdsaPrivateKey[T]) SKI() T {
	pubKey, _ := e.PublicKey()
	return pubKey.SKI()
}

func (e *ecdsaPrivateKey[T]) PublicKey() (Key[T], error) {
	return &ecdsaPublicKey[T]{
		algorithm: e.algorithm,
		publicKey: &e.privateKey.PublicKey}, nil
}

func (e *ecdsaPrivateKey[T]) Sign(msg T) (signature T, err error) {
	digest := sha256.New()
	if _, err = digest.Write(toBytes(msg)); err != nil {
		return T(""), fmt.Errorf("failed to write message bytes to hash: %w", err)
	}

	payload, err := e.privateKey.Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
	if err != nil {
		return T(""), fmt.Errorf("failed to sign message: %w", err)
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(e.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(digest.Sum(nil)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (e *ecdsaPrivateKey[T]) Verify(_, _ T) (bool, error) {
	return false, ErrUnsupportedMethod
}

func (e *ecdsaPrivateKey[T]) Encrypt(_ T) (ciphertext T, err error) {
	return T(""), ErrUnsupportedMethod
}

func (e *ecdsaPrivateKey[T]) Decrypt(_ T) (plaintext T, err error) {
	return T(""), ErrUnsupportedMethod
}

type ecdsaPublicKey[T DataType] struct {
	publicKey *ecdsa.PublicKey
	algorithm Algorithm
}

func (e *ecdsaPublicKey[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(e.algorithm)
}

func (e *ecdsaPublicKey[T]) Bytes() (key T, err error) {
	pkcs8Encoded, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		return T(""), fmt.Errorf("failed to marshal public key: %v", err)
	}
	return T(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8Encoded})), nil
}

func (e *ecdsaPublicKey[T]) SKI() T {
	raw := elliptic.MarshalCompressed(e.publicKey.Curve, e.publicKey.X, e.publicKey.Y)

	hash := sha256.New()
	hash.Write(raw)
	return T(hash.Sum(nil))
}

func (e *ecdsaPublicKey[T]) PublicKey() (Key[T], error) {
	return e, nil
}

func (e *ecdsaPublicKey[T]) Sign(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (e *ecdsaPublicKey[T]) Verify(msg, signature T) (bool, error) {
	dataBytes := toString(signature)

	parts := strings.SplitN(dataBytes, ".", 3)
	if len(parts) != 3 {
		return false, errors.New("invalid signature format: should contain three parts separated by '.'")
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse signature type: %v", err)
	}

	if Algorithm(typ) != e.algorithm {
		return false, errors.New("algorithm type mismatch: the provided type does not match the expected algorithm")
	}

	digest := sha256.New()
	if _, err = digest.Write(toBytes(msg)); err != nil {
		return false, fmt.Errorf("failed to write message bytes to hash: %v", err)
	}

	oldDigest, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to decode digest from signature: %v", err)
	}

	if !bytes.Equal(digest.Sum(nil), oldDigest) {
		return false, errors.New("digest mismatch: the calculated digest does not match the provided digest")
	}

	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("failed to decode payload from signature: %v", err)
	}

	if !ecdsa.VerifyASN1(e.publicKey, digest.Sum(nil), payload) {
		return false, errors.New("ECDSA verification failed: the signature is not valid for the provided data")
	}

	return true, nil
}

func (e *ecdsaPublicKey[T]) Encrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

func (e *ecdsaPublicKey[T]) Decrypt(_ T) (T, error) {
	return T(""), ErrUnsupportedMethod
}

type ecdsaKeyGeneratorImpl[T DataType] struct{}

func (e *ecdsaKeyGeneratorImpl[T]) KeyGen(alg Algorithm) (Key[T], error) {
	var curve elliptic.Curve
	switch alg {
	case EcdsaP256:
		curve = elliptic.P256()
	case EcdsaP384:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %v", GetTypeByAlgorithm(alg))
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key for [%v]: %w", curve, err)
	}

	return &ecdsaPrivateKey[T]{
		algorithm:  alg,
		privateKey: privateKey,
	}, nil
}

type ecdsaKeyImportImpl[T DataType] struct{}

func (e *ecdsaKeyImportImpl[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
	data, err := checkAndConvertKey(raw)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return &ecdsaPrivateKey[T]{
			algorithm:  alg,
			privateKey: key.(*ecdsa.PrivateKey),
		}, nil
	}

	key, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return &ecdsaPublicKey[T]{
			algorithm: alg,
			publicKey: key.(*ecdsa.PublicKey),
		}, nil
	}

	return nil, fmt.Errorf("unsupported algorithm: %v", GetTypeByAlgorithm(alg))
}
