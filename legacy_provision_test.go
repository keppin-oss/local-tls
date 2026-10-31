package localtls

// Legacy Protector-based provisioning, retained only as test code.
//
// This path persisted exported private keys through a caller-supplied
// Protector and renewed the server certificate in place with a new key. It was
// removed from the public library surface before OSS publication; it is kept
// here only because existing tests still use it. It must not be reintroduced
// into production code.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	caKeyFile     = "ca-key.enc"
	serverKeyFile = "server-key.enc"
)

// Protector encrypts and decrypts sensitive material.
// The production implementation is coordinated with installer/service
// architecture (ADR-0010). CNG/KSP is the preferred direction for
// later Windows machine key storage.
type Protector interface {
	Protect(plaintext []byte) ([]byte, error)
	Unprotect(ciphertext []byte) ([]byte, error)
}

// PlatformProtector returns the platform-appropriate Protector.
// Machine-scoped key protection is not yet configured; the final
// deployment mechanism is coordinated with installer/service architecture
// (ADR-0010). This function returns an error until the machine key-store
// strategy is approved and implemented.
func PlatformProtector() (Protector, error) {
	return nil, fmt.Errorf("machine key protector not yet configured; see ADR-0010")
}

func marshaledKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return der, nil
}

// ----- legacy Protector-based provisioning (tests only) -----

// Provision provisions local TLS using a Protector. This is kept for
// backwards-compatible tests that use exported private keys.
func Provision(dataDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error) {
	if now == nil {
		now = time.Now
	}
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	allFiles := allFilesExist(tlsDir)
	if !allFiles {
		return firstProvision(tlsDir, protector, trustStore, now)
	}
	return reload(tlsDir, protector, trustStore, now)
}

func allFilesExist(tlsDir string) bool {
	for _, name := range []string{caCertFile, caKeyFile, serverCertFile, serverKeyFile} {
		if !fileExists(filepath.Join(tlsDir, name)) {
			return false
		}
	}
	return true
}

func firstProvision(tlsDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error) {
	if anyFileExists(tlsDir) {
		return Material{}, fmt.Errorf("incomplete local TLS material in %s; remove directory or restore all files", tlsDir)
	}
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return Material{}, fmt.Errorf("create tls directory: %w", err)
	}
	nowTime := now()
	caCert, caKey, err := generateCA(nowTime)
	if err != nil {
		return Material{}, fmt.Errorf("generate CA: %w", err)
	}
	serverCert, serverKey, err := generateServerCert(nowTime, caCert, caKey)
	if err != nil {
		return Material{}, fmt.Errorf("generate server certificate: %w", err)
	}
	caKeyDER, err := marshaledKey(caKey)
	if err != nil {
		return Material{}, fmt.Errorf("marshal CA key: %w", err)
	}
	caKeyProtected, err := protector.Protect(caKeyDER)
	if err != nil {
		return Material{}, fmt.Errorf("protect CA key: %w", err)
	}
	serverKeyDER, err := marshaledKey(serverKey)
	if err != nil {
		return Material{}, fmt.Errorf("marshal server key: %w", err)
	}
	serverKeyProtected, err := protector.Protect(serverKeyDER)
	if err != nil {
		return Material{}, fmt.Errorf("protect server key: %w", err)
	}
	if err := atomicWrite(filepath.Join(tlsDir, caCertFile), caCert.Raw, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, "ca-key.enc"), caKeyProtected, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), serverCert.Raw, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, "server-key.enc"), serverKeyProtected, 0600); err != nil {
		return Material{}, err
	}
	if err := trustStore.InstallTrust(caCert.Raw); err != nil {
		return Material{}, fmt.Errorf("install CA in trust store: %w", err)
	}
	return materialFrom(caCert, caKey, serverCert, serverKey), nil
}

func reload(tlsDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error) {
	caCert, caKey, err := loadCA(tlsDir, protector)
	if err != nil {
		return Material{}, fmt.Errorf("load CA: %w", err)
	}
	serverCert, serverKey, err := loadServer(tlsDir, protector)
	if err != nil {
		return Material{}, fmt.Errorf("load server certificate: %w", err)
	}
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		return Material{}, fmt.Errorf("server certificate was not issued by our CA: %w", err)
	}
	if err := validateSAN(serverCert); err != nil {
		return Material{}, err
	}
	state, trustErr := trustStore.VerifyTrust(caCert.Raw)
	if trustErr != nil {
		return Material{}, fmt.Errorf("verify CA trust: %w", trustErr)
	}
	if state != TrustHealthy {
		return Material{}, fmt.Errorf("CA not trusted: trust state is %s (elevated provisioning/repair required)", state)
	}
	needsRenewal := false
	if nowTime := now(); nowTime.After(serverCert.NotAfter) || serverCert.NotAfter.Sub(nowTime) <= RenewalThreshold {
		needsRenewal = true
	}
	if needsRenewal {
		newServerCert, newServerKey, err := generateServerCert(now(), caCert, caKey)
		if err != nil {
			return Material{}, fmt.Errorf("renew server certificate: %w", err)
		}
		serverKeyDER, err := marshaledKey(newServerKey)
		if err != nil {
			return Material{}, fmt.Errorf("marshal renewed server key: %w", err)
		}
		serverKeyProtected, err := protector.Protect(serverKeyDER)
		if err != nil {
			return Material{}, fmt.Errorf("protect renewed server key: %w", err)
		}
		if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), newServerCert.Raw, 0600); err != nil {
			return Material{}, err
		}
		if err := atomicWrite(filepath.Join(tlsDir, "server-key.enc"), serverKeyProtected, 0600); err != nil {
			return Material{}, err
		}
		serverCert = newServerCert
		serverKey = newServerKey
	}
	return materialFrom(caCert, caKey, serverCert, serverKey), nil
}

func loadCA(tlsDir string, protector Protector) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	protected, err := os.ReadFile(filepath.Join(tlsDir, "ca-key.enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("read protected CA key: %w", err)
	}
	keyDER, err := protector.Unprotect(protected)
	if err != nil {
		return nil, nil, fmt.Errorf("unprotect CA key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected key type %T", key)
	}
	if err := verifyKeyMatch(cert, ecKey); err != nil {
		return nil, nil, fmt.Errorf("CA cert/key mismatch: %w", err)
	}
	return cert, ecKey, nil
}

func loadServer(tlsDir string, protector Protector) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server certificate: %w", err)
	}
	protected, err := os.ReadFile(filepath.Join(tlsDir, "server-key.enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("read protected server key: %w", err)
	}
	keyDER, err := protector.Unprotect(protected)
	if err != nil {
		return nil, nil, fmt.Errorf("unprotect server key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected key type %T", key)
	}
	if err := verifyKeyMatch(cert, ecKey); err != nil {
		return nil, nil, fmt.Errorf("server cert/key mismatch: %w", err)
	}
	return cert, ecKey, nil
}

func anyFileExists(tlsDir string) bool {
	for _, name := range []string{caCertFile, caKeyFile, serverCertFile, serverKeyFile} {
		if fileExists(filepath.Join(tlsDir, name)) {
			return true
		}
	}
	return false
}

func materialFrom(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serverCert *x509.Certificate, serverKey *ecdsa.PrivateKey) Material {
	return Material{
		Certificate:         tlsCertFromMaterial(serverCert, serverKey),
		CACertificate:       caCert,
		ServerCertificate:   serverCert,
		CAFingerprintSHA256: sha256.Sum256(caCert.Raw),
	}
}

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

func tlsCertFromMaterial(cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}
