/*
Package dipper

Package crypto provides a set of cryptographic utilities in Go.

It includes interfaces and functions for handling cryptographic keys, such as Key, KeyGenerator, and KeyImporter.
These interfaces provide methods for key generation, import, signing, verifying, encrypting, and decrypting.

The package supports a variety of cryptographic algorithms, including HMAC SHA, AES CBC, AES GCM, ECDSA, and RSA.

Example usage:

	key, err := KeyImport[string]("123456", AesCbc128)
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

This will encrypt the string "hello world" using the AES CBC 128 algorithm and then decrypt it back to the original string.
*/
package dipper
