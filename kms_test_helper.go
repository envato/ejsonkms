package ejsonkms

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// mockKMSClient is a mock implementation of kmsiface.KMSAPI for testing.
// It performs a simple passthrough of plaintext <-> ciphertext for testing purposes.
type mockKMSClient struct {
	kmsiface.KMSAPI
}

func (m *mockKMSClient) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	// Simply return the plaintext as ciphertext for testing
	return &kms.EncryptOutput{
		CiphertextBlob: input.Plaintext,
	}, nil
}

func (m *mockKMSClient) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	// Simply return the ciphertext as plaintext for testing
	return &kms.DecryptOutput{
		Plaintext: input.CiphertextBlob,
	}, nil
}

// newMockKMSClient returns a mock KMS client for testing
func newMockKMSClient(awsRegion string) kmsiface.KMSAPI {
	return &mockKMSClient{}
}

// setupMockKMS sets up the mock KMS client for testing and returns a cleanup function
func setupMockKMS() func() {
	original := kmsClientFactory
	kmsClientFactory = newMockKMSClient
	return func() {
		kmsClientFactory = original
	}
}
