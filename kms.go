package main

import (
	"encoding/base64"
	"flag"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

func decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion string) (key string, err error) {
	kmsSvc := newKmsClient(awsRegion)

	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)

	params := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}
	resp, err := kmsSvc.Decrypt(params)
	if err != nil {
		log.Fatalf("unable to decrypt parameter: %v", err)
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
		log.Fatalf("unable to encrypt parameter: %v", err)
	}

	encodedPrivKey := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	return encodedPrivKey, nil
}

func newKmsClient(awsRegion string) *kms.KMS {
	awsSession := session.Must(session.NewSession())
	awsSession.Config.WithRegion(awsRegion)
	if flag.Lookup("test.v") != nil { // is there a better way to do this?
		fakeKmsEndpoint := os.Getenv("FAKE_AWSKMS_URL")
		if len(fakeKmsEndpoint) == 0 {
			fakeKmsEndpoint = "http://localhost:8080"
		}
		return kms.New(awsSession, aws.NewConfig().WithEndpoint(fakeKmsEndpoint))
	}
	return kms.New(awsSession)
}
