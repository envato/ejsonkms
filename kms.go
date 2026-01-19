package ejsonkms

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

func decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion string) (key string, err error) {
	kmsSvc := newKmsClient(awsRegion)

	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)

	params := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}
	resp, err := kmsSvc.Decrypt(params)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt parameter: %v", err)
	}
	return string(resp.Plaintext), nil
}

func encryptPrivateKeyWithKMS(privateKey, kmsKeyID, awsRegion string) (key string, err error) {
	kmsSvc := newKmsClient(awsRegion)
	params := &kms.EncryptInput{
		KeyId:     &kmsKeyID,
		Plaintext: []byte(privateKey),
	}
	resp, err := kmsSvc.Encrypt(params)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt parameter: %v", err)
	}

	encodedPrivKey := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	return encodedPrivKey, nil
}

func newKmsClient(awsRegion string) kmsiface.KMSAPI {
	awsConfig := aws.NewConfig()
	if awsRegion != "" {
		awsConfig = awsConfig.WithRegion(awsRegion)
	}
	fakeKmsEndpoint := os.Getenv("FAKE_AWSKMS_URL")
	if fakeKmsEndpoint != "" {
		awsConfig = awsConfig.WithEndpoint(fakeKmsEndpoint)
	}
	awsSession := session.Must(session.NewSession(awsConfig))
	return kms.New(awsSession)
}
