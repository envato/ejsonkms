package main

import (
	"encoding/base64"
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

func decryptPrivateKeyWithKMS(privateKeyEnc string, awsRegion string) (key string, err error) {
	awsSession := session.Must(session.NewSession())
	awsSession.Config.WithRegion(awsRegion)
	kmsSvc := kms.New(awsSession)

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
	awsSession := session.Must(session.NewSession())
	awsSession.Config.WithRegion(awsRegion)
	kmsSvc := kms.New(awsSession)
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
