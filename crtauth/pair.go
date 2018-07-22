package crtauth

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// Pair represents a certificate and private key pair along with the key size in bits.
type Pair struct {
	Cert    *x509.Certificate
	Key     crypto.PrivateKey
	KeyBits int
}

// NewPair creates a new pair of certificate and private key.
//
// A template is used to populate the Cert field of the Pair structure. The Cert's validity
// is calculated from the current moment and expires after template.ValidForDays days. Serial
// number is not provided in template, but for convenience is also populated as a randomly
// generated big.Int number.
//
// The Key field is initialized with a randomly generated private key of type rsa.PrivateKey
// or ecdsa.PrivateKey, depending on the requested key size.
// Currently only the following bit sizes are supported: 224, 256, 384, 521, 1024, 2048, 3072, 4096.
// If template.KeyBits < 1024 Key is an ecdsa.PrivateKey.
// If template.KeyBits >= 1024 Key is an rsa.PrivateKey.
func NewPair(template *Template) (*Pair, error) {
	cert, err := template.to509()
	if err != nil {
		cert = &x509.Certificate{}
	}
	key, err := genPrivKey(template.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key for pair: %s", err)
	}
	return &Pair{
		Cert:    cert,
		Key:     key,
		KeyBits: template.KeyBits,
	}, nil
}

// NewCAPair creates a new certificate/key pair with KeyUsage suitable for use as root certificate
// of a certification authority.
func NewCAPair(template *Template) (*Pair, error) {
	pair, err := NewPair(template)
	if err != nil {
		return nil, err
	}
	pair.Cert.IsCA = true
	pair.Cert.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return pair, nil
}

// NewServerPair creates a new certificate/key pair with KeyUsage suitable for server authentication.
func NewServerPair(template *Template) (*Pair, error) {
	pair, err := NewPair(template)
	if err != nil {
		return nil, err
	}
	pair.Cert.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if pair.Cert.ExtKeyUsage == nil {
		pair.Cert.ExtKeyUsage = []x509.ExtKeyUsage{}
	}
	pair.Cert.ExtKeyUsage = append(pair.Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	return pair, nil
}

// LoadCert reads, decodes and parses the Cert portion of the pair from the given reader.
func (p *Pair) LoadCert(reader io.Reader) error {
	cert, err := readPEMCert(reader)
	if err != nil {
		return fmt.Errorf("failed reading certificate: %s", err)
	}
	p.Cert = cert
	return nil
}

// LoadKey reads, decodes and parses the Key portion of the pair from the given reader.
func (p *Pair) LoadKey(reader io.Reader) error {
	key, err := readPEMKey(reader)
	if err != nil {
		return fmt.Errorf("failed reading key: %s", err)
	}
	p.Key = key
	return nil
}

// LoadFiles opens, reads, decodes and parses both the Cert and Key fields from the specified files.
func (p *Pair) LoadFiles(certPath string, keyPath string) error {
	certFile, err := os.Open(certPath)
	if err != nil {
		return fmt.Errorf("failed opening cert file %s: %s", certPath, err)
	}
	defer certFile.Close()
	err = p.LoadCert(certFile)
	if err != nil {
		return err
	}

	keyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("failed opening key file %s: %s", keyPath, err)
	}
	defer keyFile.Close()
	err = p.LoadKey(keyFile)
	if err != nil {
		return err
	}

	return nil
}

// WriteCert PEM encodes and writes the Cert portion of the pair to the given writer.
func (p *Pair) WriteCert(writer io.Writer) error {
	certPem := pemBlockForCert(p.Cert)
	err := pem.Encode(writer, certPem)
	if err != nil {
		return fmt.Errorf("failed to write certificate as PEM: %s", err)
	}
	return nil
}

// WriteKey PEM encodes and writes the Key portion of the pair to the given writer.
func (p *Pair) WriteKey(writer io.Writer) error {
	keyPem, err := pemBlockForKey(p.Key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %s", err)
	}
	err = pem.Encode(writer, keyPem)
	if err != nil {
		return fmt.Errorf("failed to write key: %s", err)
	}
	return nil
}

// WriteFiles PEM encodes and writes both the Cert and Key fields of the pair to the specified files.
func (p *Pair) WriteFiles(certPath string, keyPath string) error {
	certFile, err := mkdirAndCreateFile(certPath, 0700, 0644)
	if err != nil {
		return fmt.Errorf("failed to create cert file %s: %s", certPath, err)
	}
	defer certFile.Close()
	err = p.WriteCert(certFile)
	if err != nil {
		return fmt.Errorf("failed to write to cert file %s: %s", certPath, err)
	}

	keyFile, err := mkdirAndCreateFile(keyPath, 0700, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file %s: %s", keyPath, err)
	}
	defer keyFile.Close()
	err = p.WriteKey(keyFile)
	if err != nil {
		return fmt.Errorf("failed to write to key file %s: %s", keyPath, err)
	}
	keyFile.Close()
	// TODO: Modify file ACL in Windows while creating the file, not after the fact
	err = restrictKeyPermissions(keyPath)
	if err != nil {
		return fmt.Errorf("failed to restrict permissions to %s file: %s", keyPath, err)
	}
	return nil
}

// PubKey returns the public key of the pair's private key. Supports only
// private keys of types rsa.PrivateKey and ecdsa.PrivateKey.
func (p *Pair) PubKey() interface{} {
	return publicKey(p.Key)
}

// SignWith signs the certificate in the receiver with the given parent certificate.
// The Cert field of the receiver is replaced (recreated) with a new instance,
// containing the updated certificate.
// The argument passed to parent must have both Cert and Key fields populated.
func (p *Pair) SignWith(parent *Pair) error {
	if parent.Cert == nil || parent.Key == nil {
		return errors.New("can't sign certificate with incomplete parent pair")
	}
	p.Cert.Issuer = parent.Cert.Subject
	if p == parent {
		p.Cert.IsCA = true
		p.Cert.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	pubKey := publicKey(p.Key)
	derBytes, err := x509.CreateCertificate(rand.Reader, p.Cert, parent.Cert, pubKey, parent.Key)
	if err != nil {
		return fmt.Errorf("failed to create signed certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %s", err)
	}
	p.Cert = cert
	return nil
}
