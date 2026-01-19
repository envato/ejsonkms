package ejsonkms

import (
	"bytes"
	"encoding/json"
	"errors"
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
	data, err := os.ReadFile(ejsonFilePath)
	if err != nil {
		return nil, err
	}

	privateKeyEnc, err := extractPrivateKeyEnc(data)
	if err != nil {
		return nil, err
	}

	kmsDecryptedPrivateKey, err := decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	if err := ejson.Decrypt(bytes.NewReader(data), &output, "", kmsDecryptedPrivateKey); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func extractPrivateKeyEnc(data []byte) (string, error) {
	var ejsonKmsKeys EjsonKmsKeys

	if err := json.Unmarshal(data, &ejsonKmsKeys); err != nil {
		return "", err
	}

	if len(ejsonKmsKeys.PrivateKeyEnc) == 0 {
		return "", errors.New("missing _private_key_enc field")
	}

	return ejsonKmsKeys.PrivateKeyEnc, nil
}

// findPrivateKeyEnc reads a file and extracts the private key
func findPrivateKeyEnc(ejsonFilePath string) (string, error) {
	data, err := os.ReadFile(ejsonFilePath)
	if err != nil {
		return "", err
	}
	return extractPrivateKeyEnc(data)
}
