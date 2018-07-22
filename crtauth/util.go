package crtauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// pemBlockForCert creates PEM block for the ASN.1 DER content of a certificate.
func pemBlockForCert(cert *x509.Certificate) *pem.Block {
	return &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
}

// readPEMCert reads, decodes and parses a PEM certificate into a x509.Certificate structure.
func readPEMCert(cert io.Reader) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadAll(cert)
	if err != nil {
		return nil, fmt.Errorf("could not read cert PEM: %s", err)
	}

	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("CERTIFICATE block not found")
		}
		blockType := strings.ToUpper(block.Type)
		blockType = strings.TrimSpace(blockType)
		if blockType == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		pemBytes = rest
	}
}

// readPEMKey reads, decodes and parses a PEM encoded private key (RSA or EC)
// into a rsa.PrivateKey or ecdsa.PrivateKey.
func readPEMKey(cert io.Reader) (crypto.PrivateKey, error) {
	pemBytes, err := ioutil.ReadAll(cert)
	if err != nil {
		return nil, fmt.Errorf("could not read key PEM: %s", err)
	}

	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("PRIVATE KEY block not found")
		}
		blockType := strings.ToUpper(block.Type)
		blockType = strings.TrimSpace(blockType)
		if blockType == "RSA PRIVATE KEY" {
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		} else if blockType == "EC PRIVATE KEY" {
			return x509.ParseECPrivateKey(block.Bytes)
		}
		pemBytes = rest
	}
}

// daysToDuration converts number of days into time.Duration.
func daysToDuration(days int) time.Duration {
	return time.Duration(days) * 24 * time.Hour
}

// genPrivKey generates a rsa.PrivateKey or ecdsa.PrivateKey depending on the requested key size.
// If bits < 1024 returns an ecdsa.PrivateKey.
// If bits >= 1024 returns an rsa.PrivateKey.
func genPrivKey(bits int) (crypto.PrivateKey, error) {
	var priv crypto.PrivateKey
	var err error
	if bits < 1024 {
		var ec elliptic.Curve
		switch bits {
		case 224:
			ec = elliptic.P224()
		case 256:
			ec = elliptic.P256()
		case 384:
			ec = elliptic.P384()
		case 521:
			ec = elliptic.P521()
		}

		priv, err = ecdsa.GenerateKey(ec, rand.Reader)
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, bits)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s", err)
	}
	return priv, nil
}

// ensureDirExists creates a directory and all necessary parent directories
// (with given permissions), unless it already exists.
func ensureDirExists(dir string, perm os.FileMode) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, perm)
		if err != nil {
			return fmt.Errorf("cannot create directory %s: %s", dir, err)
		}
	}
	return nil
}

// mkdirAndCreateFile creates a new file with the specified permission alogn
// with all necessasy parent directories.
// Directories are created with the permissions bits specified in dirPerm.
// The file is created with the permissions bits specified in filePerm.
func mkdirAndCreateFile(name string, dirPerm, filePerm os.FileMode) (*os.File, error) {
	err := ensureDirExists(filepath.Dir(name), dirPerm)
	if err != nil {
		return nil, fmt.Errorf("file %s not created: %s", name, err)
	}
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, filePerm)
}

// restrictKeyPermissions removes all permissions from a key file except for
// the owner of the file.
func restrictKeyPermissions(keyPath string) error {
	// TODO: Use Windows API instead of invoking an external command
	if runtime.GOOS == "windows" {
		// First, remove explicitly set permissions
		args := []string{keyPath, "/reset"}
		cmd := exec.Command("icacls", args...)
		err := cmd.Run()
		if err != nil {
			return err
		}

		// Then, remove inherited permissions and replace owner's with Full control
		args = []string{keyPath, "/inheritance:r", "/grant:r", `CREATOR OWNER:F`}
		cmd = exec.Command("icacls", args...)
		return cmd.Run()
	}
	return nil
}
