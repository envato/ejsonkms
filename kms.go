package main

import (
	"encoding/base64"
	"flag"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var fakeKmsEndpoint = "http://awskms:8080"

func decryptPrivateKeyWithKMS(privateKeyEnc string, awsRegion string) (key string, err error) {
	kmsSvc := newKmsClient(awsRegion)

	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)

	params := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}
	resp, err := kmsSvc.Decrypt(params)
	if err != nil {
		log.Fatalf("Unable to decrypt parameter: %v", err)
	}
	return string(resp.Plaintext), nil
}

func encryptPrivateKeyWithKMS(privateKey string, kmsKeyID string, awsRegion string) (key string, err error) {
	kmsSvc := newKmsClient(awsRegion)
	params := &kms.EncryptInput{
		KeyId:     &kmsKeyID,
		Plaintext: []byte(privateKey),
	}
	resp, err := kmsSvc.Encrypt(params)
	if err != nil {
		log.Fatalf("Unable to encrypt parameter: %v", err)
	}

	encodedPrivKey := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	return encodedPrivKey, nil
}

func newKmsClient(awsRegion string) *kms.KMS {
	awsSession := session.Must(session.NewSession())
	awsSession.Config.WithRegion(awsRegion)
	if flag.Lookup("test.v") != nil { // is there a better way to do this?
		return kms.New(awsSession, aws.NewConfig().WithEndpoint(fakeKmsEndpoint))
	}
	return kms.New(awsSession)
}
