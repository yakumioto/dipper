# Dipper

[![Go Reference](https://pkg.go.dev/badge/github.com/yakumioto/dipper.svg)](https://pkg.go.dev/github.com/yakumioto/dipper)
[![Go Report Card](https://goreportcard.com/badge/github.com/yakumioto/dipper)](https://goreportcard.com/report/github.com/yakumioto/dipper)
[![codecov](https://codecov.io/gh/yakumioto/dipper/graph/badge.svg?token=HqETyi1zYV)](https://codecov.io/gh/yakumioto/dipper)
[![actions](https://github.com/yakumioto/dipper/actions/workflows/ci.yaml/badge.svg)](https://github.com/yakumioto/dipper/actions)

一个快速易用方便的 Go 语言的加密工具库、采用统一的接口实现支持密钥生成、密钥导入导出、加密解密、签名验签、密码哈希 等功能。

## 特征

基于 Go 范型特性，支持 `[]byte` 、`string`。

统一的输出格式：

- 密文格式：{算法标识}.{密文}、{算法标识}.{密文}.{签名}。
- 密文+签名格式：{算法标识}.{密文}.{签名}
- 签名格式：{算法标识}.{消息摘要}.{签名}
- 哈希格式：{算法标识}.{哈希值}
- 
## 支持的算法

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

## 安装

```
go get github.com/yakumioto/dipper
```

## 使用示例

加密：使用 `AES_GCM_256` 加密和解密字符串

```go
package main

import (
	"fmt"

	"github.com/yakumioto/dipper"
	"github.com/yakumioto/dipper/types"
)

func main() {
	key, err := crypto.KeyImport[string](types.AesGcm256, "123456")
	if err != nil {
		panic(err)
	}

	ciphertext, err := key.Encrypt("hello world")
	if err != nil {
		panic(err)
	}
	fmt.Println(ciphertext)
	// aes_gcm_256.RYrO4e+d2xslDQgZiZWQgClwVr/jZygLb3VMP5COwvxOBg6OSpHf

	plaintext, err := key.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(plaintext)
	// hello world
}
```

签名：使用 `ECDSA_P256` 签名和验签字符串

```go
package main

import (
	"fmt"

	"github.com/yakumioto/dipper"
	"github.com/yakumioto/dipper/types"
)

func main() {
	privKey, err := dipper.KeyGenerate[string](types.EcdsaP256)
	if err != nil {
		panic(err)
	}

	signature, err := privKey.Sign("hello world")
	if err != nil {
		panic(err)
	}
	fmt.Println(signature)
	// ecdsa_p256.uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek.MEQCIBFl8IcfPldpN5eTOW+rKmrTyLTx7zZsdFv56suUGy2VAiA9ZIBt7i9WmQwazwtpki5M+8oZlFBqovITQzykZDfQBA

	pubKey, err := privKey.PublicKey()
	if err != nil {
		panic(err)
	}

	verified, err := pubKey.Verify("hello world", signature)
	if err != nil {
		panic(err)
	}

	fmt.Println(verified)
	// true
}
```

密码哈希：使用 `ARGON2ID` 哈希密码

```go
package main

import (
	"fmt"

	"github.com/yakumioto/dipper"
	"github.com/yakumioto/dipper/argon2"
	"github.com/yakumioto/dipper/types"
)

func main() {
	key, err := dipper.KeyGenerate[string](types.Argon2,
		argon2.WithMemory[string](65536),
		argon2.WithTime[string](4),
		argon2.WithThreads[string](4),
	)
	if err != nil {
		panic(err)
	}

	signature, err := key.Sign("hello world")
	if err != nil {
		panic(err)
	}
	fmt.Println(signature)
	// argon2.argon2id$v=19$m=65536,t=4,p=4$BYzGXsTNx3Vy86vpqWU7+Q$AgOiaQEMnPudblmI4rTHSmFgZcNAgND4aQM+KwtdK40

	verified, err := key.Verify("hello world", signature)
	if err != nil {
		panic(err)
	}

	fmt.Println(verified)
	// true
}
```

## 社群交流

Telegram：<https://t.me/gocryptosuite>

## 感谢

项目受到了以下项目的启发：

- Hyperledger Fabric： https://github.com/hyperledger/fabric
- Bitwarden：https://bitwarden.com/help/bitwarden-security-white-paper

## 贡献

欢迎贡献！请随时提交拉取请求或打开议题。

## 许可证

本项目采用 MIT 许可证。