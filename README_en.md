# Dipper

[![Go Reference](https://pkg.go.dev/badge/github.com/yakumioto/dipper.svg)](https://pkg.go.dev/github.com/yakumioto/dipper)
[![Go Report Card](https://goreportcard.com/badge/github.com/yakumioto/dipper)](https://goreportcard.com/report/github.com/yakumioto/dipper)
[![codecov](https://codecov.io/gh/yakumioto/dipper/graph/badge.svg?token=HqETyi1zYV)](https://codecov.io/gh/yakumioto/dipper)
[![actions](https://github.com/yakumioto/dipper/actions/workflows/ci.yaml/badge.svg)](https://github.com/yakumioto/dipper/actions)

A fast, easy-to-use, and convenient cryptographic library for Go, featuring a unified interface that supports key generation, key import/export, encryption/decryption, signing/verification, and password hashing.

## Features

Unified output formats:

- Ciphertext format: `{algorithm identifier}.{ciphertext}`, `{algorithm identifier}.{ciphertext}.{signature}`.
- Ciphertext + signature format: `{algorithm identifier}.{ciphertext}.{signature}`
- Signature format: `{algorithm identifier}.{message digest}.{signature}`
- Hash format: `{algorithm identifier}.{hash value}`

## Supported Algorithms

| Hasher      | Encryption & Decryption | Signing & Verification | Hashing & Verification |
|:------------|:-----------------------:|:----------------------:|:----------------------:|
| AES_CBC_128 |            ✔            |                        |                        |
| AES_CBC_192 |            ✔            |                        |                        |
| AES_CBC_256 |            ✔            |                        |                        |
| AES_GCM_128 |            ✔            |                        |                        |
| AES_GCM_192 |            ✔            |                        |                        |
| AES_GCM_256 |            ✔            |                        |                        |
| Chacha20    |            ✔            |                        |                        |
| XChacha20   |            ✔            |                        |                        |
| RSA_1024    |            ✔            |           ✔            |                        |
| RSA_2048    |            ✔            |           ✔            |                        |
| RSA_4096    |            ✔            |           ✔            |                        |
| ECDSA_P256  |                         |           ✔            |                        |
| ECDSA_P384  |                         |           ✔            |                        |
| ECDSA_P521  |                         |           ✔            |                        |
| HMAC_SHA256 |                         |           ✔            |                        |
| HMAC_SHA512 |                         |           ✔            |                        |
| ARGON2I     |                         |                        |           ✔            |
| ARGON2ID    |                         |                        |           ✔            |
| PBKDF2_SHA256 |                       |                        |           ✔            |
| PBKDF2_SHA512 |                       |                        |           ✔            |

## Installation

```
go get github.com/yakumioto/dipper
```

## Usage Examples

Encryption: Encrypting and Decrypting a String Using `AES_GCM_256`

```go
package main

import (
	"fmt"

	"github.com/yakumioto/dipper"
	"github.com/yakumioto/dipper/types"
)

func main() {
	key, err := crypto.KeyImport(types.AesGcm256, "123456")
	if err != nil {
		panic(err)
	}

	ciphertext, err := key.Encrypt([]byte("hello world"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(ciphertext))
	// aes_gcm_256.RYrO4e+d2xslDQgZiZWQgClwVr/jZygLb3VMP5COwvxOBg6OSpHf

	plaintext, err := key.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
	// hello world
}
```

Signing: Signing and Verifying a String Using `ECDSA_P256`

```go
package main

import (
	"fmt"

	"github.com/yakumioto/dipper"
	"github.com/yakumioto/dipper/types"
)

func main() {
	privKey, err := dipper.KeyGenerate(types.EcdsaP256)
	if err != nil {
		panic(err)
	}

	signature, err := privKey.Sign([]byte("hello world"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(signature))
	// ecdsa_p256.uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek.MEQCIBFl8IcfPldpN5eTOW+rKmrTyLTx7zZsdFv56suUGy2VAiA9ZIBt7i9WmQwazwtpki5M+8oZlFBqovITQzykZDfQBA

	pubKey, err := privKey.PublicKey()
	if err != nil {
		panic(err)
	}

	verified, err := pubKey.Verify([]byte("hello world"), signature)
	if err != nil {
		panic(err)
	}

	fmt.Println(verified)
	// true
}
```

Password Hashing: Hashing a Password Using `ARGON2ID`

```go
package main

import (
	"fmt"

	"github.com/yakumioto/dipper"
	"github.com/yakumioto/dipper/argon2"
	"github.com/yakumioto/dipper/types"
)

func main() {
	key, err := dipper.KeyGenerate(types.Argon2,
		argon2.WithMemory(65536),
		argon2.WithTime(4),
		argon2.WithThreads(4),
	)
	if err != nil {
		panic(err)
	}

	signature, err := key.Sign([]byte("hello world"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(signature))
	// argon2.argon2id$v=19$m=65536,t=4,p=4$BYzGXsTNx3Vy86vpqWU7+Q$AgOiaQEMnPudblmI4rTHSmFgZcNAgND4aQM+KwtdK40

	verified, err := key.Verify([]byte("hello world"), signature)
	if err != nil {
		panic(err)
	}

	fmt.Println(verified)
	// true
}
```

## Community

Join our Telegram group: <https://t.me/godipper>
## Acknowledgments

This project is inspired by:

Hyperledger Fabric: <https://github.com/hyperledger/fabric>

Bitwarden: <https://bitwarden.com/help/bitwarden-security-white-paper>

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues.

## License

This project is licensed under the MIT License.