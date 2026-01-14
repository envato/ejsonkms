package ejsonkms

import (
	"path/filepath"
	"strings"
)

// FileFormat represents the format of a secrets file
type FileFormat int

const (
	// FormatJSON represents JSON format (.ejson)
	FormatJSON FileFormat = iota
	// FormatYAML represents YAML format (.eyml, .eyaml)
	FormatYAML
)

// DetectFormat determines the file format based on the file extension
func DetectFormat(filePath string) FileFormat {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".eyml", ".eyaml":
		return FormatYAML
	default:
		return FormatJSON
	}
}

// IsYAMLFile returns true if the file path has a YAML extension
func IsYAMLFile(filePath string) bool {
	return DetectFormat(filePath) == FormatYAML
}
