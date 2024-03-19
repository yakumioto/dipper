# go-crypto-suite

[![Go Reference](https://pkg.go.dev/badge/github.com/yakumioto/go-crypto-suite.svg)](https://pkg.go.dev/github.com/yakumioto/go-crypto-suite)
[![Go Report Card](https://goreportcard.com/badge/github.com/yakumioto/go-crypto-suite)](https://goreportcard.com/report/github.com/yakumioto/go-crypto-suite)
[![codecov](https://codecov.io/gh/yakumioto/go-crypto-suite/graph/badge.svg?token=HqETyi1zYV)](https://codecov.io/gh/yakumioto/go-crypto-suite)
[![actions](https://github.com/yakumioto/go-crypto-suite/actions/workflows/ci.yaml/badge.svg)](https://github.com/yakumioto/go-crypto-suite/actions)

go-crypto-suite is a Go library that provides a set of cryptographic utilities. It includes interfaces and functions for handling cryptographic keys, such as Key, KeyGenerator, and KeyImporter. These interfaces provide methods for key generation, import, signing, verifying, encrypting, and decrypting.

## Features

- Supports a variety of cryptographic algorithms, including:
    - HMAC SHA (SHA256, SHA512)
    - AES CBC (128-bit, 192-bit, 256-bit)
    - AES GCM (128-bit, 192-bit, 256-bit)
    - ECDSA (P256, P384)
    - RSA (1024-bit, 2048-bit, 4096-bit)
- Provides a simple and consistent interface for working with cryptographic keys
- Allows keys to be represented as either byte slices or strings
- Includes functions for key generation and import

## Installation

To install go-crypto-suite, use `go get`:

```
go get github.com/yakumioto/go-crypto-suite
```

## Usage

Here's a basic example that demonstrates encrypting and decrypting a string using AES-CBC-128:

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

This will output:
```
hello world
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the terms of the MIT license.