package ejsonkms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// mockKMSClient is an in-process stand-in for KMS. Encrypt returns the
// plaintext as the ciphertext and Decrypt returns the ciphertext as the
// plaintext, so the two round-trip. Every call is recorded, as is the
// region each client was requested for.
type mockKMSClient struct {
	regions      []string
	encryptCalls []*kms.EncryptInput
	decryptCalls []*kms.DecryptInput
	factoryErr   error
	encryptErr   error
	decryptErr   error
}

func (m *mockKMSClient) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	m.encryptCalls = append(m.encryptCalls, input)
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	return &kms.EncryptOutput{
		CiphertextBlob: append([]byte(nil), input.Plaintext...),
		KeyId:          input.KeyId,
	}, nil
}

func (m *mockKMSClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	m.decryptCalls = append(m.decryptCalls, input)
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	return &kms.DecryptOutput{
		Plaintext: append([]byte(nil), input.CiphertextBlob...),
	}, nil
}

// setupMockKMS routes every KMS call to the returned mock until restore is
// called. Defer restore so later tests use the real client.
func setupMockKMS() (mock *mockKMSClient, restore func()) {
	mock = &mockKMSClient{}
	original := kmsClientFactory
	kmsClientFactory = func(_ context.Context, awsRegion string) (kmsAPI, error) {
		mock.regions = append(mock.regions, awsRegion)
		if mock.factoryErr != nil {
			return nil, mock.factoryErr
		}
		return mock, nil
	}
	return mock, func() { kmsClientFactory = original }
}
