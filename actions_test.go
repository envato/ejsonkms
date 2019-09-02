package main

import (
	"bytes"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestEnv(t *testing.T) {
	outputBuffer := new(bytes.Buffer)
	output = outputBuffer

	// ensure that output returns to os.Stdout
	defer func() {
		output = os.Stdout
	}()

	Convey("Env", t, func() {
		err := envAction("testdata/test.ejson", false, "us-east-1")

		Convey("should return decrypted values as shell exports", func() {
			So(err, ShouldBeNil)
			actualOutput := outputBuffer.String()
			So(actualOutput, ShouldContainSubstring, "export my_secret=secret123")
		})
	})

	Convey("Env with no private key", t, func() {
		err := envAction("testdata/test_no_private_key.ejson", false, "us-east-1")

		Convey("should fail", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "Missing _private_key_enc")
		})
	})
}
