package localtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cert, key, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("CA certificate must have IsCA=true")
	}
	if !cert.BasicConstraintsValid {
		t.Fatal("CA must have BasicConstraintsValid")
	}
	if cert.Subject.CommonName != caCN {
		t.Fatalf("CA CN = %q", cert.Subject.CommonName)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("CA algorithm = %v", cert.PublicKeyAlgorithm)
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("CA key must be P-256")
	}
	if cert.NotBefore.After(now) {
		t.Fatal("CA NotBefore is in the future")
	}
	expectedExpiry := now.Add(caValidity)
	if diff := cert.NotAfter.Sub(expectedExpiry); diff > time.Second || diff < -time.Second {
		t.Fatalf("CA NotAfter = %v, expected ~%v", cert.NotAfter, expectedExpiry)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA must have KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		t.Fatal("CA must not advertise KeyUsageCRLSign")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		t.Fatal("CA must not advertise KeyUsageDigitalSignature")
	}
	if cert.KeyUsage != x509.KeyUsageCertSign {
		t.Fatalf("CA KeyUsage = %v, expected only KeyUsageCertSign", cert.KeyUsage)
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Fatalf("CA must encode MaxPathLen=0 (MaxPathLen=%d, MaxPathLenZero=%v)", cert.MaxPathLen, cert.MaxPathLenZero)
	}

	// Self-signature verification
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("CA self-signature check: %v", err)
	}
}

func TestGenerateServerCert(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}

	cert, key, err := generateServerCert(now, caCert, caKey)
	if err != nil {
		t.Fatalf("generateServerCert: %v", err)
	}
	if cert.IsCA {
		t.Fatal("server certificate must not be CA")
	}
	if cert.Subject.CommonName != serverCN {
		t.Fatalf("server CN = %q", cert.Subject.CommonName)
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("server key must be P-256")
	}

	foundServerAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
			break
		}
	}
	if !foundServerAuth {
		t.Fatal("server certificate must have ExtKeyUsageServerAuth")
	}

	expectedExpiry := now.Add(serverValidity)
	if diff := cert.NotAfter.Sub(expectedExpiry); diff > time.Second || diff < -time.Second {
		t.Fatalf("server NotAfter = %v, expected ~%v", cert.NotAfter, expectedExpiry)
	}
}

func TestServerCertSANs(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	cert, _, err := generateServerCert(now, caCert, caKey)
	if err != nil {
		t.Fatalf("generateServerCert: %v", err)
	}

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "localhost" {
		t.Fatalf("DNSNames = %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("IPAddresses length = %d", len(cert.IPAddresses))
	}
	found4, found6 := false, false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			found4 = true
		}
		if ip.Equal(net.IPv6loopback) {
			found6 = true
		}
	}
	if !found4 || !found6 {
		t.Fatal("IP SAN must contain 127.0.0.1 and ::1")
	}
}

func TestServerCertChainsToCA(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	serverCert, _, err := generateServerCert(now, caCert, caKey)
	if err != nil {
		t.Fatalf("generateServerCert: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: now}
	if _, err := serverCert.Verify(opts); err != nil {
		t.Fatalf("server cert does not chain to CA: %v", err)
	}
}

func TestCABasicConstraintsPathLenZero(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cert, _, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("CA must have IsCA=true")
	}
	if !cert.BasicConstraintsValid {
		t.Fatal("CA must have BasicConstraintsValid=true")
	}
	if cert.MaxPathLen != 0 {
		t.Fatalf("MaxPathLen = %d, expected 0", cert.MaxPathLen)
	}
	if !cert.MaxPathLenZero {
		t.Fatal("MaxPathLenZero must be true so the zero value is encoded as an explicit constraint")
	}
}

func TestCAMinimalKeyUsage(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cert, _, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	if cert.KeyUsage != x509.KeyUsageCertSign {
		t.Fatalf("CA KeyUsage = %v, expected only KeyUsageCertSign", cert.KeyUsage)
	}
}

func TestSuccessiveLeafIssuanceUnderPathLenZeroCA(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	for i := 0; i < 3; i++ {
		leaf, _, err := generateServerCert(now, caCert, caKey)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		opts := x509.VerifyOptions{Roots: roots, CurrentTime: now}
		if _, err := leaf.Verify(opts); err != nil {
			t.Fatalf("leaf %d does not chain to CA despite MaxPathLen=0: %v", i, err)
		}
	}
}

func TestSubordinateCAChainRejected(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}

	subCA, subCAKey, err := newSubordinateCA(now, caCert, caKey)
	if err != nil {
		t.Fatalf("build subordinate CA: %v", err)
	}
	leaf, _, err := generateServerCert(now, subCA, subCAKey)
	if err != nil {
		t.Fatalf("build leaf under subordinate CA: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(subCA)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	if _, err := leaf.Verify(opts); err == nil {
		t.Fatal("subordinate CA chain must be rejected because of the CA MaxPathLen=0 constraint")
	}
}

// newSubordinateCA constructs a test-only subordinate CA certificate signed by
// the given parent CA. It exists purely to prove the path-length constraint.
func newSubordinateCA(now time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Keppin Test Sub CA"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func TestRandomSerialNonZeroPositive(t *testing.T) {
	for i := 0; i < 20; i++ {
		serial, err := randomSerial()
		if err != nil {
			t.Fatalf("randomSerial: %v", err)
		}
		if serial.Sign() <= 0 {
			t.Fatalf("serial = %v", serial)
		}
		if serial.Cmp(big.NewInt(0)) <= 0 {
			t.Fatal("serial must be positive")
		}
	}
}

func TestVerifyKeyMatchSuccess(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cert, key, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	if err := verifyKeyMatch(cert, key); err != nil {
		t.Fatalf("verifyKeyMatch: %v", err)
	}
}

func TestVerifyKeyMatchMismatch(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cert, _, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err := verifyKeyMatch(cert, otherKey); err == nil {
		t.Fatal("should fail with mismatched key")
	}
}

func TestServerKeyMatch(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, _ := generateCA(now)
	cert, key, _ := generateServerCert(now, caCert, caKey)
	if err := verifyKeyMatch(cert, key); err != nil {
		t.Fatalf("verifyKeyMatch: %v", err)
	}
}

func TestVerifyPublicKeyMatchSigner(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cert, key, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	if err := verifyPublicKeyMatch(cert, &key.PublicKey); err != nil {
		t.Fatalf("verifyPublicKeyMatch: %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	if err := verifyPublicKeyMatch(cert, &otherKey.PublicKey); err == nil {
		t.Fatal("verifyPublicKeyMatch should fail with a mismatched public key")
	}
}
