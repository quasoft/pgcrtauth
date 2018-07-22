package cmd

import (
	"fmt"
	"strconv"
	"strings"
)

// isValidKeySize tests if the provided string for key size is one of the supported values.
func isValidKeySize(keySize string) bool {
	switch keySize {
	case
		"P224", "P256", "P384", "P521", "1024", "2048", "3072", "4096":
		return true
	}
	return false
}

// parseKeyBits converts the provided key size string to integer value with the number of bits.
func parseKeyBits(keySize string) (int, error) {
	if !isValidKeySize(keySize) {
		return 0, fmt.Errorf("invalid key size '%s'", keySize)
	}
	if strings.HasPrefix(strings.ToUpper(keySize), "P") {
		keySize = keySize[1:]
	}
	numBits, err := strconv.Atoi(keySize)
	if err != nil {
		return 0, fmt.Errorf("key size '%s' cannot be converted to integer value", keySize)
	}

	return numBits, nil
}
