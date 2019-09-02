package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Shopify/ejson"
)

func encryptAction(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("at least one file path must be given")
	}
	for _, filePath := range args {
		n, err := ejson.EncryptFileInPlace(filePath)
		if err != nil {
			return err
		}
		fmt.Printf("Wrote %d bytes to %s.\n", n, filePath)
	}
	return nil
}

func decryptAction(args []string, awsRegion string, outFile string) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one file path must be given")
	}
	ejsonFilePath := args[0]

	decrypted, err := decrypt(ejsonFilePath, awsRegion)
	if err != nil {
		return err
	}

	target := os.Stdout
	if outFile != "" {
		target, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer func() { _ = target.Close() }()
	}

	_, err = target.Write(decrypted)
	return err
}

func keygenAction(args []string, kmsKeyID string, awsRegion string, outFile string) error {
	pub, priv, privKeyEnc, err := keygen(kmsKeyID, awsRegion)
	if err != nil {
		return err
	}

	fmt.Printf("Private Key: %s\n", priv)
	target := os.Stdout
	if outFile != "" {
		target, err = os.Create(outFile)
		if err != nil {
			return err
		}
		defer func() { _ = target.Close() }()
	} else {
		fmt.Printf("EJSON File:\n")
	}

	_, err = fmt.Fprintf(target, "{\n  \"_public_key\": \"%s\",\n  \"_private_key_enc\": \"%s\"\n}", pub, privKeyEnc)
	if err != nil {
		return err
	}
	return nil
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
