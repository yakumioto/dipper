package dipper

import (
	"fmt"

	"github.com/yakumioto/dipper/types"
	"github.com/yakumioto/dipper/utils"
)

func ExampleKeyImport() {
	utils.RandomSize = func(len int) ([]byte, error) {
		b := make([]byte, len)
		for i := 0; i < len; i++ {
			b[i] = 'a'
		}
		return b, nil
	}

	key, err := KeyImport(types.AesCbc128, "123456")
	if err != nil {
		panic(err)
	}

	ciphertext, err := key.Encrypt([]byte("hello world"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(ciphertext))

	plaintext, err := key.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))
	// Output:
	// aes_cbc_128.YWFhYWFhYWFhYWFhYWFhYWv1wt6aTe92jzFCoVBvNYU
	// hello world
}
