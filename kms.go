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

func decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion string) (key string, err error) {
	ctx := context.Background()
	kmsSvc, err := newKmsClient(ctx, awsRegion)
	if err != nil {
		return "", err
	}

	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)

	params := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}
	resp, err := kmsSvc.Decrypt(ctx, params)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt parameter: %v", err)
	}
	return string(resp.Plaintext), nil
}

func encryptPrivateKeyWithKMS(privateKey, kmsKeyID, awsRegion string) (key string, err error) {
	ctx := context.Background()
	kmsSvc, err := newKmsClient(ctx, awsRegion)
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

func newKmsClient(ctx context.Context, awsRegion string) (*kms.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %v", err)
	}
	fakeKmsEndpoint := os.Getenv("FAKE_AWSKMS_URL")
	if len(fakeKmsEndpoint) != 0 {
		return kms.NewFromConfig(cfg, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(fakeKmsEndpoint)
		}), nil
	}
	return kms.NewFromConfig(cfg), nil
}
