package ejsonkms

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// kmsAPI is the subset of the KMS client this package calls.
type kmsAPI interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

var kmsClientFactory = newKmsClient

func decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion string) (key string, err error) {
	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)
	if err != nil {
		return "", fmt.Errorf("unable to decode encrypted private key: %v", err)
	}

	ctx := context.Background()
	kmsSvc, err := kmsClientFactory(ctx, awsRegion)
	if err != nil {
		return "", err
	}

	params := &kms.DecryptInput{
		CiphertextBlob: encryptedValue,
	}
	resp, err := kmsSvc.Decrypt(ctx, params)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt parameter: %v", err)
	}
	return string(resp.Plaintext), nil
}

func encryptPrivateKeyWithKMS(privateKey, kmsKeyID, awsRegion string) (key string, err error) {
	ctx := context.Background()
	kmsSvc, err := kmsClientFactory(ctx, awsRegion)
	if err != nil {
		return "", err
	}

	params := &kms.EncryptInput{
		KeyId:     &kmsKeyID,
		Plaintext: []byte(privateKey),
	}
	resp, err := kmsSvc.Encrypt(ctx, params)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt parameter: %v", err)
	}

	encodedPrivKey := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	return encodedPrivKey, nil
}

func newKmsClient(ctx context.Context, awsRegion string) (kmsAPI, error) {
	// The SDK treats an empty region as unset, so the environment and shared
	// config still apply when awsRegion is "".
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %v", err)
	}

	var clientOpts []func(*kms.Options)
	if fakeKmsEndpoint := os.Getenv("FAKE_AWSKMS_URL"); fakeKmsEndpoint != "" {
		clientOpts = append(clientOpts, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(fakeKmsEndpoint)
		})
	}
	return kms.NewFromConfig(cfg, clientOpts...), nil
}
