package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/Shopify/ejson"
)

// EjsonKmsKeys - keys used in an EjsonKms file
type EjsonKmsKeys struct {
	PublicKey     string `json:"_public_key"`
	PrivateKeyEnc string `json:"_private_key_enc"`
	PrivateKey    string
}

// Keygen generates keys and prepares an EJSON file with them
func Keygen(kmsKeyID, awsRegion string) (EjsonKmsKeys, error) {
	var ejsonKmsKeys EjsonKmsKeys
	pub, priv, err := ejson.GenerateKeypair()
	if err != nil {
		return ejsonKmsKeys, err
	}

	privKeyEnc, err := encryptPrivateKeyWithKMS(priv, kmsKeyID, awsRegion)
	if err != nil {
		return ejsonKmsKeys, err
	}

	ejsonKmsKeys = EjsonKmsKeys{
		PublicKey:     pub,
		PrivateKeyEnc: privKeyEnc,
		PrivateKey:    priv,
	}

	return ejsonKmsKeys, nil
}

// Decrypt decrypts an EJSON file
func Decrypt(ejsonFilePath, awsRegion string) ([]byte, error) {
	privateKeyEnc, err := findPrivateKeyEnc(ejsonFilePath)
	if err != nil {
		return nil, err
	}

	kmsDecryptedPrivateKey, err := decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion)
	if err != nil {
		return nil, err
	}

	decrypted, err := ejson.DecryptFile(ejsonFilePath, "", kmsDecryptedPrivateKey)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func findPrivateKeyEnc(ejsonFilePath string) (key string, err error) {
	var (
		ejsonKmsKeys EjsonKmsKeys
	)

	file, err := os.Open(ejsonFilePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(data, &ejsonKmsKeys)
	if err != nil {
		return "", err
	}

	if len(ejsonKmsKeys.PrivateKeyEnc) == 0 {
		return "", errors.New("missing _private_key_enc field")
	}

	return ejsonKmsKeys.PrivateKeyEnc, nil
}
