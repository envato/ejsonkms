package ejsonkms

import (
	"testing"

	"github.com/kami-zh/go-capturer"
	. "github.com/smartystreets/goconvey/convey"
)

func TestEnv(t *testing.T) {
	Convey("Env", t, func() {
		out := capturer.CaptureOutput(func() {
			err := EnvAction("testdata/test.ejson", "us-east-1", false)
			So(err, ShouldBeNil)
		})

		Convey("should return decrypted values as shell exports", func() {
			So(out, ShouldContainSubstring, "export my_secret=secret123")
		})
	})

	Convey("Env with no private key", t, func() {
		err := EnvAction("testdata/test_no_private_key.ejson", "us-east-1", false)

		Convey("should fail", func() {
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "missing _private_key_enc")
		})
	})
}
