package ejsonkms

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	. "github.com/smartystreets/goconvey/convey"
)

func TestKMSPrivateKeyRoundTrip(t *testing.T) {
	Convey("With a mocked KMS client", t, func() {
		mock, restore := setupMockKMS()
		defer restore()

		Convey("encrypting then decrypting a private key returns the original", func() {
			enc, err := encryptPrivateKeyWithKMS("my-private-key", "alias/test", "us-east-1")
			So(err, ShouldBeNil)
			So(enc, ShouldEqual, "bXktcHJpdmF0ZS1rZXk=")
			So(len(mock.encryptCalls), ShouldEqual, 1)
			So(*mock.encryptCalls[0].KeyId, ShouldEqual, "alias/test")
			So(string(mock.encryptCalls[0].Plaintext), ShouldEqual, "my-private-key")

			dec, err := decryptPrivateKeyWithKMS(enc, "us-east-1")
			So(err, ShouldBeNil)
			So(dec, ShouldEqual, "my-private-key")
			So(len(mock.decryptCalls), ShouldEqual, 1)
			So(string(mock.decryptCalls[0].CiphertextBlob), ShouldEqual, "my-private-key")
			So(mock.regions, ShouldResemble, []string{"us-east-1", "us-east-1"})
		})

		Convey("a client construction failure is returned from encrypt", func() {
			mock.factoryErr = errors.New("no config")
			_, err := encryptPrivateKeyWithKMS("k", "alias/test", "us-east-1")
			So(err, ShouldEqual, mock.factoryErr)
			So(len(mock.encryptCalls), ShouldEqual, 0)
		})

		Convey("a client construction failure is returned from decrypt", func() {
			mock.factoryErr = errors.New("no config")
			_, err := decryptPrivateKeyWithKMS("YWJj", "us-east-1")
			So(err, ShouldEqual, mock.factoryErr)
			So(len(mock.decryptCalls), ShouldEqual, 0)
		})

		Convey("a KMS encrypt failure is reported", func() {
			mock.encryptErr = errors.New("boom")
			_, err := encryptPrivateKeyWithKMS("k", "alias/test", "us-east-1")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "unable to encrypt parameter: boom")
		})

		Convey("a KMS decrypt failure is reported", func() {
			mock.decryptErr = errors.New("boom")
			_, err := decryptPrivateKeyWithKMS("YWJj", "us-east-1")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "unable to decrypt parameter: boom")
		})

		Convey("invalid base64 ciphertext is rejected before calling KMS", func() {
			_, err := decryptPrivateKeyWithKMS("not base64!", "us-east-1")
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "unable to decode")
			So(len(mock.decryptCalls), ShouldEqual, 0)
		})
	})
}

func TestNewKmsClient(t *testing.T) {
	// Loading config does not resolve credentials, so these cases need no
	// KMS endpoint. Each case pins the environment it depends on.
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("FAKE_AWSKMS_URL", "")

	options := func(t *testing.T, awsRegion string) kms.Options {
		t.Helper()
		client, err := newKmsClient(context.Background(), awsRegion)
		if err != nil {
			t.Fatalf("newKmsClient: %v", err)
		}
		return client.(*kms.Client).Options()
	}

	t.Run("uses the given region and no endpoint override", func(t *testing.T) {
		opts := options(t, "ap-southeast-2")
		if opts.Region != "ap-southeast-2" {
			t.Errorf("Region = %q, want ap-southeast-2", opts.Region)
		}
		if opts.BaseEndpoint != nil {
			t.Errorf("BaseEndpoint = %q, want nil", *opts.BaseEndpoint)
		}
	})

	t.Run("falls back to the environment region when none is given", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-west-1")
		opts := options(t, "")
		if opts.Region != "eu-west-1" {
			t.Errorf("Region = %q, want eu-west-1", opts.Region)
		}
	})

	t.Run("prefers the given region over the environment", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-west-1")
		opts := options(t, "us-east-1")
		if opts.Region != "us-east-1" {
			t.Errorf("Region = %q, want us-east-1", opts.Region)
		}
	})

	t.Run("FAKE_AWSKMS_URL overrides the endpoint", func(t *testing.T) {
		t.Setenv("FAKE_AWSKMS_URL", "http://awskms:8080")
		opts := options(t, "us-east-1")
		if opts.BaseEndpoint == nil || *opts.BaseEndpoint != "http://awskms:8080" {
			t.Errorf("BaseEndpoint = %v, want http://awskms:8080", opts.BaseEndpoint)
		}
	})
}
