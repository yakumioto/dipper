package crypto

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HmacShaKey", func() {
	Describe("key by bytes", func() {
		var (
			key       Key[[]byte]
			signature []byte
			err       error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(hmacShaKeyImportImpl[[]byte]).KeyImport([]byte("123456"), HmacSha256)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				signature, err = key.Sign([]byte("hello world"))
				Expect(err).To(BeNil())
				Expect(signature).ToNot(BeNil())
			})

			It("should be verified successfully", func() {
				Expect(key.Verify([]byte("hello world"), signature)).To(BeTrue())
			})

			It("should serialize successfully", func() {
				serialized, err := key.Bytes()
				Expect(err).To(BeNil())
				Expect(serialized).ToNot(BeNil())
			})
		})

		Context("with invalid key", func() {
			It("should fail to create key", func() {
				_, err = new(hmacShaKeyImportImpl[[]byte]).KeyImport([]byte(""), HmacSha256) // Empty key
				Expect(err).ToNot(BeNil())
			})
		})

		Context("with incorrect signature", func() {
			It("should not verify successfully", func() {
				incorrectSignature := []byte("incorrect_signature")
				Expect(key.Verify([]byte("hello world"), incorrectSignature)).To(BeFalse())
			})
		})
	})

	Describe("key by string", func() {
		var (
			key       Key[string]
			signature string
			err       error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(hmacShaKeyImportImpl[string]).KeyImport("123456", HmacSha256)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				signature, err = key.Sign("hello world")
				Expect(err).To(BeNil())
				Expect(signature).ToNot(BeNil())
			})

			It("should be verified successfully", func() {
				Expect(key.Verify("hello world", signature)).To(BeTrue())
			})

			It("should serialize successfully", func() {
				serialized, err := key.Bytes()
				Expect(err).To(BeNil())
				Expect(serialized).ToNot(BeNil())
			})
		})

		Context("with invalid key", func() {
			It("should fail to create key", func() {
				_, err = new(hmacShaKeyImportImpl[[]byte]).KeyImport([]byte(""), HmacSha256) // Empty key
				Expect(err).ToNot(BeNil())
			})
		})

		Context("with incorrect signature", func() {
			It("should not verify successfully", func() {
				incorrectSignature := "incorrect_signature"
				Expect(key.Verify("hello world", incorrectSignature)).To(BeFalse())
			})
		})
	})
})

func FuzzHmacShaKeyImportImpl_KeyImport(f *testing.F) {
	f.Fuzz(func(t *testing.T, key []byte) {
		_, err := new(hmacShaKeyImportImpl[[]byte]).KeyImport(key, HmacSha512)
		if err != nil {
			t.Skip()
		}
	})
}
