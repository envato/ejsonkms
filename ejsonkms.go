package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/Shopify/ejson"
)

// Keygen generates keys and prepares an EJSON file with them
func Keygen(kmsKeyID, awsRegion string) (string, string, string, error) {
	pub, priv, err := ejson.GenerateKeypair()
	if err != nil {
		return "", "", "", err
	}

	privKeyEnc, err := encryptPrivateKeyWithKMS(priv, kmsKeyID, awsRegion)
	if err != nil {
		return "", "", "", err
	}

	return pub, priv, privKeyEnc, nil
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
		obj map[string]interface{}
		ks  string
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

	err = json.Unmarshal(data, &obj)
	if err != nil {
		return "", err
	}

	k, ok := obj["_private_key_enc"]
	if !ok {
		return "", errors.New("Missing _private_key_enc field")
	}
	ks, ok = k.(string)
	if !ok {
		return "", errors.New("Couldn't cast _private_key_enc to string")
	}
	return ks, nil
}
