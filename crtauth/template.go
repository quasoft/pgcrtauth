package crtauth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"
)

// Template contains a subset of the most frequently used certificate parameters
// and is used for convenient initialization of x509.Certificate or Spec structures.
type Template struct {
	Organization string
	CommonName   string
	HostNames    []string
	ValidForDays int
	KeyBits      int
}

// NewTemplate creates a new template with default parameters:
// 	- ValidForDays = 365 days
// 	- KeyBits = 256 (ie. EC P256 key)
func NewTemplate() *Template {
	return &Template{
		ValidForDays: 365,
		KeyBits:      256,
	}
}

// to509 applies the template to an empty x509.Certificate and returns that
// structure. Certificate validity is calculated from the current moment and
// expires after ValidForDays.
// Serial number is a randomly generated big.Int number.
func (t *Template) to509() (*x509.Certificate, error) {
	var cert x509.Certificate
	serial, err := randSerial()
	if err != nil {
		return nil, fmt.Errorf("To509() failed: %s", err)
	}
	duration := daysToDuration(t.ValidForDays)

	cert.SerialNumber = serial
	cert.Subject = pkix.Name{
		Organization: []string{t.Organization},
		CommonName:   t.CommonName,
	}
	cert.NotBefore = time.Now()
	cert.NotAfter = cert.NotBefore.Add(duration)
	cert.BasicConstraintsValid = true

	if len(t.HostNames) > 0 {
		for _, h := range t.HostNames {
			if ip := net.ParseIP(h); ip != nil {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			} else {
				cert.DNSNames = append(cert.DNSNames, h)
			}
		}
	}

	return &cert, nil
}
