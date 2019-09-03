package main

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestKeygen(t *testing.T) {
	Convey("Keygen", t, func() {
		ejsonKmsKeys, err := Keygen("bc436485-5092-42b8-92a3-0aa8b93536dc", "us-east-1")
		Convey("should return three strings that look key-like", func() {
			So(err, ShouldBeNil)
			So(ejsonKmsKeys.PublicKey, ShouldNotEqual, ejsonKmsKeys.PrivateKey)
			So(ejsonKmsKeys.PublicKey, ShouldNotContainSubstring, "00000")
			So(ejsonKmsKeys.PrivateKey, ShouldNotContainSubstring, "00000")
			So(ejsonKmsKeys.PrivateKeyEnc, ShouldNotContainSubstring, "00000")
		})
	})
}

func TestDecrypt(t *testing.T) {
	Convey("Decrypt", t, func() {
		decrypted, err := Decrypt("testdata/test.ejson", "us-east-1")
		Convey("should return decrypted values", func() {
			So(err, ShouldBeNil)
			json := string(decrypted[:])
			So(json, ShouldContainSubstring, `"my_secret": "secret123"`)
		})
	})
	Convey("Decrypt with no private key", t, func() {
		_, err := Decrypt("testdata/test_no_private_key.ejson", "us-east-1")
		Convey("should fail", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Missing _private_key_enc")
		})
	})
}
