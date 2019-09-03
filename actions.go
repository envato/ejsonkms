package main

import (
	"fmt"
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

func decryptAction(args []string, awsRegion, outFile string) error {
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

func keygenAction(args []string, kmsKeyID, awsRegion, outFile string) error {
	pub, priv, privKeyEnc, err := Keygen(kmsKeyID, awsRegion)
	if err != nil {
		return err
	}

	fmt.Println("Private Key:", priv)
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

	_, err = fmt.Fprintf(target, "{\n  \"_public_key\": \"%s\",\n  \"_private_key_enc\": \"%s\"\n}", pub, privKeyEnc)
	if err != nil {
		return err
	}
	return nil
}

func envAction(ejsonFilePath, awsRegion string, quiet bool) error {
	exportFunc := ExportEnv
	if quiet {
		exportFunc = ExportQuiet
	}
	privateKeyEnc, err := findPrivateKeyEnc(ejsonFilePath)
	if err != nil {
		return err
	}

	kmsDecryptedPrivateKey, err := decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion)
	if err != nil {
		return err
	}

	return ExportSecrets(ejsonFilePath, kmsDecryptedPrivateKey, exportFunc)
}
