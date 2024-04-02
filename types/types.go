package types

// DataType is an interface that represents the data type of a cryptographic key.
// It can be either a byte slice or a string.
type DataType interface {
	~[]byte | ~string
}

type Algorithm = int

type AlgorithmType string

const (
	HashType       Algorithm = 100
	SymmetricType  Algorithm = 200
	AsymmetricType Algorithm = 300
)

// hash algorithms type
const (
	HmacSha256 Algorithm = iota + HashType + 1
	HmacSha512
	Pbkdf2Sha256
	Pbkdf2Sha512

	TypeHmacSha256   AlgorithmType = "HMAC_SHA256"
	TypeHmacSha512   AlgorithmType = "HMAC_SHA512"
	TypePbkdf2Sha256 AlgorithmType = "PBKDF2_SHA256"
	TypePbkdf2Sha512 AlgorithmType = "PBKDF2_SHA512"
)

// symmetric algorithms type
const (
	AesCbc128 Algorithm = iota + SymmetricType + 1
	AesCbc192
	AesCbc256
	AesGcm128
	AesGcm192
	AesGcm256

	TypeAesCbc128 AlgorithmType = "AES_CBC_128"
	TypeAesCbc192 AlgorithmType = "AES_CBC_192"
	TypeAesCbc256 AlgorithmType = "AES_CBC_256"
	TypeAesGcm128 AlgorithmType = "AES_GCM_128"
	TypeAesGcm192 AlgorithmType = "AES_GCM_192"
	TypeAesGcm256 AlgorithmType = "AES_GCM_256"
)

// asymmetric algorithms type
const (
	EcdsaP256 Algorithm = iota + AsymmetricType + 1
	EcdsaP384
	EcdsaP521
	Rsa1024
	Rsa2048
	Rsa4096

	TypeEcdsaP256 AlgorithmType = "ECDSA_P256"
	TypeEcdsaP384 AlgorithmType = "ECDSA_P384"
	TypeEcdsaP521 AlgorithmType = "ECDSA_P521"
	TypeRsa1024   AlgorithmType = "RSA_1024"
	TypeRsa2048   AlgorithmType = "RSA_2048"
	TypeRsa4096   AlgorithmType = "RSA_4096"
)

var (
	algorithms = map[AlgorithmType]Algorithm{
		TypeHmacSha256:   HmacSha256,
		TypeHmacSha512:   HmacSha512,
		TypePbkdf2Sha256: Pbkdf2Sha256,
		TypePbkdf2Sha512: Pbkdf2Sha512,

		TypeAesCbc128: AesCbc128,
		TypeAesCbc192: AesCbc192,
		TypeAesCbc256: AesCbc256,
		TypeAesGcm128: AesGcm128,
		TypeAesGcm192: AesGcm192,
		TypeAesGcm256: AesGcm256,

		TypeEcdsaP256: EcdsaP256,
		TypeEcdsaP384: EcdsaP384,
		TypeEcdsaP521: EcdsaP521,
		TypeRsa1024:   Rsa1024,
		TypeRsa2048:   Rsa2048,
		TypeRsa4096:   Rsa4096,
	}

	algorithmsType = map[Algorithm]AlgorithmType{
		HmacSha256:   TypeHmacSha256,
		HmacSha512:   TypeHmacSha512,
		Pbkdf2Sha256: TypePbkdf2Sha256,
		Pbkdf2Sha512: TypePbkdf2Sha512,

		AesCbc128: TypeAesCbc128,
		AesCbc192: TypeAesCbc192,
		AesCbc256: TypeAesCbc256,
		AesGcm128: TypeAesGcm128,
		AesGcm192: TypeAesGcm192,
		AesGcm256: TypeAesGcm256,

		EcdsaP256: TypeEcdsaP256,
		EcdsaP384: TypeEcdsaP384,
		EcdsaP521: TypeEcdsaP521,

		Rsa1024: TypeRsa1024,
		Rsa2048: TypeRsa2048,
		Rsa4096: TypeRsa4096,
	}
)

// GetTypeByAlgorithm returns the corresponding algorithm type string based on the given algorithm enumeration value.
// If the given algorithm enumeration value does not exist in the known algorithm mapping, it will return an empty string.
func GetTypeByAlgorithm(algorithm Algorithm) AlgorithmType {
	return algorithmsType[algorithm]
}

// GetAlgorithmByType returns the corresponding algorithm enumeration value based on the given algorithm type string.
// If the given algorithm type string does not exist in the known algorithm mapping, it will return a zero-value algorithm enumeration value.
func GetAlgorithmByType(algorithm AlgorithmType) Algorithm {
	return algorithms[algorithm]
}
