package crypto

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EcdsaKey", func() {
	Describe("key by string", func() {
		var (
			key       Key[string]
			signature string
			err       error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(ecdsaKeyGeneratorImpl[string]).KeyGen(EcdsaP256)
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
		})
	})
})
