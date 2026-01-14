package ejsonkms

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/Shopify/ejson"
	"gopkg.in/yaml.v3"
)

// EjsonKmsKeys - keys used in an EjsonKms file
type EjsonKmsKeys struct {
	PublicKey     string `json:"_public_key" yaml:"_public_key"`
	PrivateKeyEnc string `json:"_private_key_enc" yaml:"_private_key_enc"`
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

	return decryptFile(ejsonFilePath, kmsDecryptedPrivateKey)
}

// decryptFile decrypts the file using ejson.DecryptFile, handling format conversion for YAML files
func decryptFile(filePath, privateKey string) ([]byte, error) {
	isYAML := IsYAMLFile(filePath)

	// Determine the file to decrypt (original for JSON, temp file for YAML)
	decryptPath := filePath
	if isYAML {
		tmpFile, err := createTempJSONFile(filePath)
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmpFile)
		decryptPath = tmpFile
	}

	// Both formats use the same decryption path
	decryptedJSON, err := ejson.DecryptFile(decryptPath, "", privateKey)
	if err != nil {
		return nil, err
	}

	// Convert back to YAML if needed
	if isYAML {
		return convertJSONToYAML(decryptedJSON)
	}

	return decryptedJSON, nil
}

// createTempJSONFile converts a YAML file to a temporary JSON file for decryption
func createTempJSONFile(yamlFilePath string) (string, error) {
	yamlData, err := ioutil.ReadFile(yamlFilePath)
	if err != nil {
		return "", err
	}

	var data interface{}
	if err := yaml.Unmarshal(yamlData, &data); err != nil {
		return "", err
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	tmpFile, err := ioutil.TempFile("", "ejsonkms-*.ejson")
	if err != nil {
		return "", err
	}

	if _, err := tmpFile.Write(jsonData); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}
	tmpFile.Close()

	return tmpFile.Name(), nil
}

// convertJSONToYAML converts decrypted JSON data to YAML format
func convertJSONToYAML(jsonData []byte) ([]byte, error) {
	var data interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	return yaml.Marshal(data)
}

func findPrivateKeyEnc(filePath string) (key string, err error) {
	var (
		ejsonKmsKeys EjsonKmsKeys
	)

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	if IsYAMLFile(filePath) {
		err = yaml.Unmarshal(data, &ejsonKmsKeys)
	} else {
		err = json.Unmarshal(data, &ejsonKmsKeys)
	}
	if err != nil {
		return "", err
	}

	if len(ejsonKmsKeys.PrivateKeyEnc) == 0 {
		return "", errors.New("missing _private_key_enc field")
	}

	return ejsonKmsKeys.PrivateKeyEnc, nil
}
