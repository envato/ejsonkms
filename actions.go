package ejsonkms

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Shopify/ejson"
	"github.com/Shopify/ejson2env/v2"
	"gopkg.in/yaml.v3"
)

func EncryptAction(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("at least one file path must be given")
	}
	for _, filePath := range args {
		n, err := encryptFile(filePath)
		if err != nil {
			return err
		}
		fmt.Printf("Wrote %d bytes to %s.\n", n, filePath)
	}
	return nil
}

// encryptFile encrypts a file in place, handling both JSON and YAML formats
func encryptFile(filePath string) (int, error) {
	if !IsYAMLFile(filePath) {
		return ejson.EncryptFileInPlace(filePath)
	}

	return encryptYAMLFileInPlace(filePath)
}

// encryptYAMLFileInPlace encrypts a YAML file in place, preserving comments and formatting
func encryptYAMLFileInPlace(filePath string) (int, error) {
	// Read the YAML file
	yamlData, err := os.ReadFile(filePath)
	if err != nil {
		return -1, err
	}

	// Get file mode to preserve permissions
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return -1, err
	}

	// Parse YAML into a node tree to preserve comments
	var doc yaml.Node
	if err := yaml.Unmarshal(yamlData, &doc); err != nil {
		return -1, err
	}

	// Find the public key for encryption
	publicKey, err := findPublicKeyInNode(&doc)
	if err != nil {
		return -1, err
	}

	// Walk the tree and encrypt values
	if err := encryptYAMLNode(&doc, publicKey); err != nil {
		return -1, err
	}

	// Encode back to YAML, preserving comments
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(4)
	if err := encoder.Encode(&doc); err != nil {
		return -1, err
	}
	encoder.Close()

	// Write back to file
	if err := os.WriteFile(filePath, buf.Bytes(), fileInfo.Mode()); err != nil {
		return -1, err
	}

	return buf.Len(), nil
}

// findPublicKeyInNode finds the _public_key value in a YAML node tree
func findPublicKeyInNode(node *yaml.Node) (string, error) {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return findPublicKeyInNode(node.Content[0])
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			if keyNode.Value == "_public_key" && valueNode.Kind == yaml.ScalarNode {
				return valueNode.Value, nil
			}
		}
	}

	return "", fmt.Errorf("_public_key not found in YAML file")
}

// encryptYAMLNode recursively encrypts string values in a YAML node tree
func encryptYAMLNode(node *yaml.Node, publicKey string) error {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := encryptYAMLNode(child, publicKey); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			// Skip keys starting with underscore (ejson convention)
			if len(keyNode.Value) > 0 && keyNode.Value[0] == '_' {
				continue
			}

			if err := encryptYAMLNode(valueNode, publicKey); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := encryptYAMLNode(child, publicKey); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		// Only encrypt string values that aren't already encrypted
		if node.Tag == "!!str" || node.Tag == "" {
			if !isEncrypted(node.Value) {
				encrypted, err := encryptValue(node.Value, publicKey)
				if err != nil {
					return err
				}
				node.Value = encrypted
				node.Tag = "!!str"
				node.Style = 0 // Reset style to default
			}
		}
	}
	return nil
}

// isEncrypted checks if a value is already encrypted (ejson format)
func isEncrypted(value string) bool {
	return len(value) > 3 && value[:3] == "EJ["
}

// encryptValue encrypts a single value using ejson's encryption format
func encryptValue(plaintext, publicKey string) (string, error) {
	// Create a minimal JSON document for ejson to encrypt
	data := map[string]interface{}{
		"_public_key": publicKey,
		"value":       plaintext,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	var inBuf, outBuf bytes.Buffer
	inBuf.Write(jsonData)
	if _, err := ejson.Encrypt(&inBuf, &outBuf); err != nil {
		return "", err
	}

	// Parse the encrypted JSON to get the encrypted value
	var result map[string]interface{}
	if err := json.Unmarshal(outBuf.Bytes(), &result); err != nil {
		return "", err
	}

	encrypted, ok := result["value"].(string)
	if !ok {
		return "", fmt.Errorf("failed to extract encrypted value")
	}

	return encrypted, nil
}

func DecryptAction(args []string, awsRegion, outFile string) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one file path must be given")
	}
	ejsonFilePath := args[0]

	decrypted, err := Decrypt(ejsonFilePath, awsRegion)
	if err != nil {
		return err
	}

	target := os.Stdout
	if outFile != "" {
		target, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer target.Close()
	}

	_, err = target.Write(decrypted)
	return err
}

// ejsonKmsFile - an ejson/eyaml file
type ejsonKmsFile struct {
	PublicKey     string `json:"_public_key" yaml:"_public_key"`
	PrivateKeyEnc string `json:"_private_key_enc" yaml:"_private_key_enc"`
}

func KeygenAction(args []string, kmsKeyID, awsRegion, outFile string) error {
	ejsonKmsKeys, err := Keygen(kmsKeyID, awsRegion)
	if err != nil {
		return err
	}

	ejsonKmsFile := ejsonKmsFile{
		PublicKey:     ejsonKmsKeys.PublicKey,
		PrivateKeyEnc: ejsonKmsKeys.PrivateKeyEnc,
	}

	var fileContent []byte
	if IsYAMLFile(outFile) {
		fileContent, err = yaml.Marshal(ejsonKmsFile)
	} else {
		fileContent, err = json.MarshalIndent(ejsonKmsFile, "", "  ")
	}
	if err != nil {
		return err
	}

	fmt.Println("Private Key:", ejsonKmsKeys.PrivateKey)
	target := os.Stdout
	if outFile != "" {
		target, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer func() { _ = target.Close() }()
	} else {
		fmt.Println("EJSON File:")
	}

	_, err = target.Write(fileContent)
	if err != nil {
		return err
	}
	return nil
}

func EnvAction(ejsonFilePath, awsRegion string, quiet bool) error {
	exportFunc := ejson2env.ExportEnv
	if quiet {
		exportFunc = ejson2env.ExportQuiet
	}
	privateKeyEnc, err := findPrivateKeyEnc(ejsonFilePath)
	if err != nil {
		return err
	}

	kmsDecryptedPrivateKey, err := decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion)
	if err != nil {
		return err
	}

	// ejson2env only supports JSON, so convert YAML to temp JSON file if needed
	readPath := ejsonFilePath
	if IsYAMLFile(ejsonFilePath) {
		tmpFile, err := createTempJSONFile(ejsonFilePath)
		if err != nil {
			return fmt.Errorf("could not convert YAML to JSON: %s", err)
		}
		defer os.Remove(tmpFile)
		readPath = tmpFile
	}

	envValues, err := ejson2env.ReadAndExtractEnv(readPath, "", kmsDecryptedPrivateKey)

	if nil != err && !ejson2env.IsEnvError(err) {
		return fmt.Errorf("could not load environment from file: %s", err)
	}

	exportFunc(os.Stdout, envValues)
	return nil
}
