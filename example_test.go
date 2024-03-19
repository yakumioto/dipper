package crypto

import "fmt"

func ExampleKeyImport() {
	RandomSize = func(len int) ([]byte, error) {
		b := make([]byte, len)
		for i := 0; i < len; i++ {
			b[i] = 'a'
		}
		return b, nil
	}

	key, err := KeyImport[string]("123456", AesCbc128)
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
	// 201.YWFhYWFhYWFhYWFhYWFhYX9QmH3XJdQhqYinPz+Bn50=
	// hello world
}
