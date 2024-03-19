package crypto

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RsaKeyByString", func() {
	var (
		key       Key[string]
		signature string
		err       error
	)

	for _, alg := range []Algorithm{Rsa1024, Rsa2048, Rsa4096} {
		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(rsaKeyGeneratorImpl[string]).KeyGen(alg)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				signature, err = key.Sign("hello world")
				Expect(err).To(BeNil())
				Expect(signature).ToNot(BeNil())
			})

			It("should be verified successfully", func() {
				publicKey, err := key.PublicKey()
				Expect(err).To(BeNil())
				Expect(publicKey.Verify("hello world", signature)).To(BeTrue())
			})

			It("should serialize and deserialize successfully", func() {
				publicKey, err := key.PublicKey()
				Expect(err).To(BeNil())
				serialized, err := publicKey.Bytes()
				Expect(err).To(BeNil())
				importedKey, err := new(rsaKeyImportImpl[string]).KeyImport(string(serialized), alg)
				Expect(err).To(BeNil())
				Expect(importedKey).ToNot(BeNil())
			})

			It("should encrypt and decrypt successfully", func() {
				publicKey, err := key.PublicKey()
				Expect(err).To(BeNil())
				encrypted, err := publicKey.Encrypt("hello world")
				Expect(err).To(BeNil())
				decrypted, err := key.Decrypt(encrypted)
				Expect(err).To(BeNil())
				Expect(decrypted).To(Equal("hello world"))
			})
		})
	}
})

var _ = Describe("RsaKeyByBytes", func() {
	var (
		key       Key[[]byte]
		signature []byte
		err       error
	)

	for _, alg := range []Algorithm{Rsa1024, Rsa2048, Rsa4096} {
		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(rsaKeyGeneratorImpl[[]byte]).KeyGen(alg)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				signature, err = key.Sign([]byte("hello world"))
				Expect(err).To(BeNil())
				Expect(signature).ToNot(BeNil())
			})

			It("should be verified successfully", func() {
				publicKey, err := key.PublicKey()
				Expect(err).To(BeNil())
				Expect(publicKey.Verify([]byte("hello world"), signature)).To(BeTrue())
			})

			It("should serialize and deserialize successfully", func() {
				publicKey, err := key.PublicKey()
				Expect(err).To(BeNil())
				serialized, err := publicKey.Bytes()
				Expect(err).To(BeNil())
				importedKey, err := new(rsaKeyImportImpl[[]byte]).KeyImport(serialized, alg)
				Expect(err).To(BeNil())
				Expect(importedKey).ToNot(BeNil())
			})

			It("should encrypt and decrypt successfully", func() {
				publicKey, err := key.PublicKey()
				Expect(err).To(BeNil())
				encrypted, err := publicKey.Encrypt([]byte("hello world"))
				Expect(err).To(BeNil())
				decrypted, err := key.Decrypt(encrypted)
				Expect(err).To(BeNil())
				Expect(decrypted).To(Equal([]byte("hello world")))
			})
		})
	}
})
