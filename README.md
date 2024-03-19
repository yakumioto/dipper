# go-crypto-suite

[![Go Reference](https://pkg.go.dev/badge/github.com/yakumioto/go-crypto-suite.svg)](https://pkg.go.dev/github.com/yakumioto/go-crypto-suite)
[![Go Report Card](https://goreportcard.com/badge/github.com/yakumioto/go-crypto-suite)](https://goreportcard.com/report/github.com/yakumioto/go-crypto-suite)
[![codecov](https://codecov.io/gh/yakumioto/go-crypto-suite/graph/badge.svg?token=HqETyi1zYV)](https://codecov.io/gh/yakumioto/go-crypto-suite)
[![actions](https://github.com/yakumioto/go-crypto-suite/actions/workflows/ci.yaml/badge.svg)](https://github.com/yakumioto/go-crypto-suite/actions)

go-crypto-suite 是一个 Go 语言的加密工具库，提供了一套用于处理密码学密钥的接口和函数，例如 Key、KeyGenerator 和 KeyImporter。这些接口提供了密钥生成、导入、签名、验证、加密和解密等方法。

## 特性

- 支持多种加密算法，包括：
    - HMAC SHA（SHA256、SHA512）
    - AES CBC（128位、192位、256位）
    - AES GCM（128位、192位、256位）
    - ECDSA（P256、P384）
    - RSA（1024位、2048位、4096位）
- 提供简单一致的密码学密钥操作接口
- 允许将密钥表示为字节切片或字符串
- 包含密钥生成和导入的函数

## 安装

要安装 go-crypto-suite，请使用 `go get`：

```
go get github.com/yakumioto/go-crypto-suite
```

## 使用

下面是一个基本的示例，演示了如何使用 AES-CBC-128 加密和解密字符串：

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

输出结果为：
```
hello world
```

## 贡献

欢迎贡献！请随时提交拉取请求或打开议题。

## 许可证

本项目采用 MIT 许可证。