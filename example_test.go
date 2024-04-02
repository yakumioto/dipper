package crypto

import (
	"fmt"

	"github.com/yakumioto/go-crypto-suite/types"
	"github.com/yakumioto/go-crypto-suite/utils"
)

func ExampleKeyImport() {
	utils.RandomSize = func(len int) ([]byte, error) {
		b := make([]byte, len)
		for i := 0; i < len; i++ {
			b[i] = 'a'
		}
		return b, nil
	}

	key, err := KeyImport[string]("123456", types.AesCbc128)
	if err != nil {
		panic(err)
	}

	ciphertext, err := key.Encrypt("hello world")
	if err != nil {
		panic(err)
	}
	fmt.Println(ciphertext)

	plaintext, err := key.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(plaintext)
	// Output:
	// 201.YWFhYWFhYWFhYWFhYWFhYWv1wt6aTe92jzFCoVBvNYU
	// hello world
}
