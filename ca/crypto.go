package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

// newCA generates a new CA cert and key
func newCA() error {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"DigiShue CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate RSA 4096 key
	caPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Generate cert
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPriv.PublicKey, caPriv)
	if err != nil {
		return err
	}

	// Write CA cert
	crtOut, err := os.Create("ca-crt.pem")
	if err != nil {
		return err
	}
	if err := pem.Encode(crtOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return err
	}

	// Write CA key
	keyOut, err := os.OpenFile("ca-key.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPriv),
	}); err != nil {
		return err
	}

	// Get CA certificate
	caCrt, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}

	// Generate cert and key for the CA
	caWebCert, caWebKey, err := newCert([]string{"ca.internal", "keyserver.internal"}, caCrt, caPriv)
	if err != nil {
		return err
	}

	// Write cert and key to files
	if err := os.WriteFile("ca-web-crt.pem", caWebCert, 0644); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("ca-web-key.pem", caWebKey, 0644); err != nil {
		log.Fatal(err)
	}

	return nil
}

// newCert generates and signs a new certificate and key
func newCert(domains []string, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	// Generate random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 65535))
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"DigiShue CA"},
		},
		DNSNames:    domains,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode cert
	crtBuf := &bytes.Buffer{}
	if err := pem.Encode(crtBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return nil, nil, err
	}

	// Encode key
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	}); err != nil {
		return nil, nil, err
	}

	return crtBuf.Bytes(), keyBuf.Bytes(), nil
}
