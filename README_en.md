# go-crypto-suite

[![Go Reference](https://pkg.go.dev/badge/github.com/yakumioto/go-crypto-suite.svg)](https://pkg.go.dev/github.com/yakumioto/go-crypto-suite)
[![Go Report Card](https://goreportcard.com/badge/github.com/yakumioto/go-crypto-suite)](https://goreportcard.com/report/github.com/yakumioto/go-crypto-suite)
[![codecov](https://codecov.io/gh/yakumioto/go-crypto-suite/graph/badge.svg?token=HqETyi1zYV)](https://codecov.io/gh/yakumioto/go-crypto-suite)
[![actions](https://github.com/yakumioto/go-crypto-suite/actions/workflows/ci.yaml/badge.svg)](https://github.com/yakumioto/go-crypto-suite/actions)

# go-crypto-suite

A fast, easy-to-use, and convenient encryption library for Go, utilizing a unified interface to support key generation, key import/export, encryption/decryption, signing/verification, and other functions.

## Features

Based on Go's generic features, it supports `[]byte` and `string`.

Unified ciphertext format: {algorithm identifier}.{ciphertext}, {algorithm identifier}.{message digest}.{signature}, {algorithm identifier}.{ciphertext}.{signature}.

- Supports symmetric keys
  - AES CBC (128-bit, 192-bit, 256-bit)
  - AES GCM (128-bit, 192-bit, 256-bit)
  - Key import
- Supports asymmetric keys
  - ECDSA (P256, P384)
  - RSA (1024-bit, 2048-bit, 4096-bit)
  - Key generation
  - Key import
- Supports hash algorithms
  - HMAC SHA (SHA256, SHA512)
  - Key import

## Installation

```
go get github.com/yakumioto/go-crypto-suite
```

## Usage

Here's a basic example demonstrating how to use AES-CBC-128 to encrypt and decrypt a string:

```go
package main

import (
    "fmt"
    
    "github.com/yakumioto/go-crypto-suite"
)

func main() {
    key, err := crypto.KeyImport[string]("123456", crypto.AesCbc128)
    if err != nil {
        panic(err)
    }

    ciphertext, err := key.Encrypt("hello world") 
    if err != nil {
        panic(err)
    }

    plaintext, err := key.Decrypt(ciphertext)
    if err != nil {
        panic(err)
    }

    fmt.Println(plaintext)
}
```

## Acknowledgements

This project was inspired by the following projects:

- Hyperledger Fabric: https://github.com/hyperledger/fabric
- Bitwarden: https://bitwarden.com/help/bitwarden-security-white-paper

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

This project is licensed under the MIT License.