package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Shopify/ejson"
	"github.com/taskcluster/shell"
)

// Original source: github.com/Shopify/ejson2env

var errNoEnv = errors.New("environment is not set in ejson")
var errEnvNotMap = errors.New("environment is not a map[string]interface{}")

// ExtractEnv extracts the environment values from the map[string]interface{}
// containing all secrets, and returns a map[string]string containing the
// key value pairs. If there's an issue (the environment key doesn't exist, for
// example), returns an error.
func ExtractEnv(secrets map[string]interface{}) (map[string]string, error) {
	rawEnv, ok := secrets["environment"]
	if !ok {
		return nil, errNoEnv
	}

	envMap, ok := rawEnv.(map[string]interface{})
	if !ok {
		return nil, errEnvNotMap
	}

	envSecrets := make(map[string]string, len(envMap))

	for key, rawValue := range envMap {

		// Only export values that convert to strings properly.
		if value, ok := rawValue.(string); ok {
			envSecrets[key] = value
		}
	}

	return envSecrets, nil
}

// ExportEnv writes the passed environment values to the passed
// io.Writer.
func ExportEnv(w io.Writer, values map[string]string) {
	for key, value := range values {
		fmt.Fprintf(w, "export %s=%s\n", key, shell.Escape(value))
	}
}

// ExportQuiet writes the passed environment values to the passed
// io.Writer in %s=%s format.
func ExportQuiet(w io.Writer, values map[string]string) {
	for key, value := range values {
		fmt.Fprintf(w, "%s=%s\n", key, shell.Escape(value))
	}
}

// ExportFunction is implemented in exportSecrets as an easy way
// to select how secrets are exported
type ExportFunction func(io.Writer, map[string]string)

// output is a pointer to the io.Writer to use. This allows us to override
// stdout for testing purposes.
var output io.Writer = os.Stdout

// ExportSecrets wraps the read, extract, and export steps. Returns
// an error if any step fails.
func ExportSecrets(filename, privateKey string, exportFunc ExportFunction) error {
	secrets, err := readSecrets(filename, privateKey)
	if nil != err {
		return fmt.Errorf("could not load ejson file: %s", err)
	}

	envValues, err := ExtractEnv(secrets)
	if !isFailure(err) {
		exportFunc(output, envValues)
	}

	// ExtractEnv does not return an error we need to handle.
	return nil
}

// ReadSecrets reads the secrets for the passed filename and
// returns them as a map[string]interface{}.
func readSecrets(filename, privateKey string) (map[string]interface{}, error) {
	secrets := make(map[string]interface{})

	decrypted, err := ejson.DecryptFile(filename, "", privateKey)
	if nil != err {
		return secrets, err
	}

	decoder := json.NewDecoder(bytes.NewReader(decrypted))

	err = decoder.Decode(&secrets)
	return secrets, err
}

// isFailure returns true if the passed error should prompt a
// failure.
func isFailure(err error) bool {
	return (nil != err && errNoEnv != err && errEnvNotMap != err)
}
