package main

import "github.com/Shopify/ejson"

func keygen(kmsKeyID string, awsRegion string) (string, string, string, error) {
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

func decrypt(ejsonFilePath string, awsRegion string) ([]byte, error) {
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
