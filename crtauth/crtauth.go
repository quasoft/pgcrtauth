// Package crtauth is used for generation of self-signed certificates for PostgreSQL servers.
package crtauth

import (
	"fmt"
	"os"
	"path/filepath"
)

// Constants for the default certificate filenames used by PostgreSQL.
const (
	RootCertFileName   = "root.crt"
	RootKeyFileName    = "root.key"
	ServerCertFileName = "server.crt"
	ServerKeyFileName  = "server.key"
)

// CA represents a certification authority.
type CA struct {
	Pair         *Pair  // Pair of x509 certificate and private key
	CertFileName string // The filename of the crt file (defaults to "root.crt")
	KeyFileName  string // The filename of the key file (defaults to "root.key")
}

// New creates a new CA structure with the default filenames for .crt and .key files.
func New() *CA {
	return &CA{
		Pair:         &Pair{},
		CertFileName: RootCertFileName,
		KeyFileName:  RootKeyFileName,
	}
}

// Init creates and initialiazies a new certification authority by generating a new
// pair of certificate and private key.
// The certificate is populated with values from the given template.
// Output files (.crt and .key) are created in the specified directory.
// Key files are created with 0600 permissions on Linux and 'Full control' for owner only on Windows.
func (ca *CA) Init(template *Template, dir string) error {
	pair, err := NewCAPair(template)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create CA directory %s: %s", dir, err)
	}

	err = pair.SignWith(pair)
	if err != nil {
		return fmt.Errorf("failed to sign certificate with CA: %s", err)
	}

	certPath := filepath.Join(dir, ca.CertFileName)
	keyPath := filepath.Join(dir, ca.KeyFileName)
	err = pair.WriteFiles(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to write CA pair to files: %s", err)
	}

	ca.Pair = pair

	return nil
}

// Load reads, decodes and parses the CA certificate and key from the specified directory and
// stores them in the CA structure. The directory should contain .crt and .key files with names
// that match ca.CertFileName and ca.KeyFileName (by default 'root.crt' and 'root.key').
func (ca *CA) Load(dir string) error {
	certPath := filepath.Join(dir, ca.CertFileName)
	keyPath := filepath.Join(dir, ca.KeyFileName)
	return ca.Pair.LoadFiles(certPath, keyPath)
}
