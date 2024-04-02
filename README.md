# go-crypto-suite

[![Go Reference](https://pkg.go.dev/badge/github.com/yakumioto/go-crypto-suite.svg)](https://pkg.go.dev/github.com/yakumioto/go-crypto-suite)
[![Go Report Card](https://goreportcard.com/badge/github.com/yakumioto/go-crypto-suite)](https://goreportcard.com/report/github.com/yakumioto/go-crypto-suite)
[![codecov](https://codecov.io/gh/yakumioto/go-crypto-suite/graph/badge.svg?token=HqETyi1zYV)](https://codecov.io/gh/yakumioto/go-crypto-suite)
[![actions](https://github.com/yakumioto/go-crypto-suite/actions/workflows/ci.yaml/badge.svg)](https://github.com/yakumioto/go-crypto-suite/actions)

一个快速易用方便的 Go 语言的加密工具库、采用统一的接口实现支持密钥生成、密钥导入导出、加密解密、签名验签、等功能。[README in English](README_en.md)

## 特征

基于 Go 范型特性，支持 `[]byte` 、`string`。

统一的密文格式：{算法标识}.{密文}、{算法标识}.{消息摘要}.{签名}、{算法标识}.{密文}.{签名}。

- 支持对称密钥
  - AES CBC（128位、192位、256位）
  - AES GCM（128位、192位、256位）
  - 密钥导入
- 支持非对称密钥
  - ECDSA（P256、P384）
  - RSA（1024位、2048位、4096位）
  - 密钥生成
  - 密钥导入
- 支持哈希算法
  - HMAC SHA（SHA256、SHA512）
  - 密钥导入

## 安装

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

## 感谢

项目受到了以下项目的启发：

- Hyperledger Fabric： https://github.com/hyperledger/fabric
- Bitwarden：https://bitwarden.com/help/bitwarden-security-white-paper

## 贡献

欢迎贡献！请随时提交拉取请求或打开议题。

## 许可证

本项目采用 MIT 许可证。