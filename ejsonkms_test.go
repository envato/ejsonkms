package main

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestKeygen(t *testing.T) {
	Convey("Keygen", t, func() {
		pub, priv, privEnc, err := Keygen("bc436485-5092-42b8-92a3-0aa8b93536dc", "us-east-1")
		Convey("should return three strings that look key-like", func() {
			So(err, ShouldBeNil)
			So(pub, ShouldNotEqual, priv)
			So(pub, ShouldNotContainSubstring, "00000")
			So(priv, ShouldNotContainSubstring, "00000")
			So(privEnc, ShouldNotContainSubstring, "00000")
		})
	})
}

func TestDecrypt(t *testing.T) {
	Convey("Decrypt", t, func() {
		So(err, ShouldBeNil)
		json := string(decrypted[:])
		So(json, ShouldContainSubstring, "\"my_secret\": \"secret123\"")
		decrypted, err := Decrypt("testdata/test.ejson", "us-east-1")
	})
}
