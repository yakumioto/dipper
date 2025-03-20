package types

type Algorithm = string

// hash algorithms type
const (
	HmacSha256   Algorithm = "hmac_sha256"
	HmacSha512   Algorithm = "hmac_sha512"
	Pbkdf2Sha256 Algorithm = "pbkdf2_sha256"
	Pbkdf2Sha512 Algorithm = "pbkdf2_sha512"
	Argon2       Algorithm = "argon2"
)

// symmetric algorithms type
const (
	AesCbc128 Algorithm = "aes_cbc_128"
	AesCbc192 Algorithm = "aes_cbc_192"
	AesCbc256 Algorithm = "aes_cbc_256"
	AesGcm128 Algorithm = "aes_gcm_128"
	AesGcm192 Algorithm = "aes_gcm_192"
	AesGcm256 Algorithm = "aes_gcm_256"
	Chacha20  Algorithm = "chacha20"
	XChacha20 Algorithm = "x_chacha20"
)

// asymmetric algorithms type
const (
	EcdsaP256 Algorithm = "ecdsa_p256"
	EcdsaP384 Algorithm = "ecdsa_p384"
	EcdsaP521 Algorithm = "ecdsa_p521"
	Rsa1024   Algorithm = "rsa_1024"
	Rsa2048   Algorithm = "rsa_2048"
	Rsa4096   Algorithm = "rsa_4096"
)
