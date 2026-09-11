package localtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/keppin-oss/local-tls/internal/identity"
)

const (
	caOrg          = identity.CertOrganization
	caCN           = identity.CACertCommonName
	serverCN       = "localhost"
	serverOrg      = identity.CertOrganization
	caValidity     = 5 * 365 * 24 * time.Hour
	serverValidity = 90 * 24 * time.Hour

	// RenewalThreshold is how close to expiry we renew the server certificate.
	RenewalThreshold = 30 * 24 * time.Hour
)

// generateCA creates a CA certificate and private key using an ephemeral key.
func generateCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if now.IsZero() {
		now = time.Now()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA private key: %w", err)
	}
	cert, err := createCACertSelfSigned(now, key)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// generateCAWithSigner creates a self-signed CA certificate using a crypto.Signer
// for the CA key. The signer must be an ECDSA P-256 key.
func generateCAWithSigner(now time.Time, signer crypto.Signer) (*x509.Certificate, error) {
	if now.IsZero() {
		now = time.Now()
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("CA signer must have an ECDSA P-256 public key")
	}
	return createCACertSelfSigned(now, signer)
}

func createCACertSelfSigned(now time.Time, signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCN,
			Organization: []string{caOrg},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return cert, nil
}

// generateServerCert creates a server certificate and ephemeral private key,
// signed by the CA key. Used only for testing with exported keys.
func generateServerCert(now time.Time, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if now.IsZero() {
		now = time.Now()
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server private key: %w", err)
	}
	cert, err := createServerCertWithPub(now, caCert, caKey, &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// generateServerCertWithSigner creates a server certificate signed by the CA signer,
// using a crypto.Signer for the server's public key. The server signer must be ECDSA P-256.
func generateServerCertWithSigner(now time.Time, caCert *x509.Certificate, caSigner, serverSigner crypto.Signer) (*x509.Certificate, error) {
	if now.IsZero() {
		now = time.Now()
	}
	pub, ok := serverSigner.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("server signer must have an ECDSA P-256 public key")
	}
	return createServerCertWithPub(now, caCert, caSigner, pub)
}

func createServerCertWithPub(now time.Time, caCert *x509.Certificate, caSigner crypto.Signer, pub crypto.PublicKey) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate server serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   serverCN,
			Organization: []string{serverOrg},
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(serverValidity),
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caSigner)
	if err != nil {
		return nil, fmt.Errorf("create server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse server certificate: %w", err)
	}
	return cert, nil
}

func randomSerial() (*big.Int, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("read random bytes for serial: %w", err)
	}
	serial := new(big.Int).SetBytes(buf)
	serial.Abs(serial)
	if serial.Sign() == 0 {
		return randomSerial()
	}
	return serial, nil
}

func verifyPublicKeyMatch(cert *x509.Certificate, pub crypto.PublicKey) error {
	switch certPub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		pubEC, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key type is %T, expected *ecdsa.PublicKey", pub)
		}
		if certPub.X.Cmp(pubEC.X) != 0 || certPub.Y.Cmp(pubEC.Y) != 0 {
			return fmt.Errorf("public key does not match certificate public key")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", certPub)
	}
}

func verifyKeyMatch(cert *x509.Certificate, key interface{}) error {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("key type is %T, expected *ecdsa.PrivateKey", key)
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fmt.Errorf("private key does not match certificate public key")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

func tlsCertFromSigner(cert *x509.Certificate, signer crypto.Signer) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
		Leaf:        cert,
	}
}

func tlsCertFromMaterial(cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}
