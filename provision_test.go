package localtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeProtector struct {
	protect   func([]byte) ([]byte, error)
	unprotect func([]byte) ([]byte, error)
}

func (fp *fakeProtector) Protect(p []byte) ([]byte, error)   { return fp.protect(p) }
func (fp *fakeProtector) Unprotect(c []byte) ([]byte, error) { return fp.unprotect(c) }

func passthroughProtector() *fakeProtector {
	return &fakeProtector{
		protect:   func(p []byte) ([]byte, error) { return p, nil },
		unprotect: func(c []byte) ([]byte, error) { return c, nil },
	}
}

type fakeTrustStore struct {
	install  func(certDER []byte) error
	remove   func(certDER []byte) error
	removeFP func([32]byte) error
	verify   func(certDER []byte) (TrustState, error)
	is       func([32]byte) (bool, error)
}

func (fts *fakeTrustStore) EnsureTrusted(der []byte) error { return fts.install(der) }
func (fts *fakeTrustStore) InstallTrust(der []byte) error  { return fts.install(der) }
func (fts *fakeTrustStore) RemoveTrust(der []byte) error   { return fts.remove(der) }
func (fts *fakeTrustStore) RemoveTrustBySHA256(fp [32]byte) error {
	if fts.removeFP != nil {
		return fts.removeFP(fp)
	}
	return fts.remove(nil)
}
func (fts *fakeTrustStore) VerifyTrust(der []byte) (TrustState, error) { return fts.verify(der) }
func (fts *fakeTrustStore) IsTrustedSHA256(fp [32]byte) (bool, error)  { return fts.is(fp) }

func okTrustStore() *fakeTrustStore {
	return &fakeTrustStore{
		install: func([]byte) error { return nil },
		remove:  func([]byte) error { return nil },
		verify:  func([]byte) (TrustState, error) { return TrustHealthy, nil },
		is:      func([32]byte) (bool, error) { return true, nil },
	}
}

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestFirstProvisionCreatesMaterial(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	material, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if material.CACertificate == nil || material.ServerCertificate == nil {
		t.Fatal("nil material")
	}

	tlsDir := filepath.Join(dataDir, tlsSubDir)
	for _, name := range []string{caCertFile, caKeyFile, serverCertFile, serverKeyFile} {
		if !fileExists(filepath.Join(tlsDir, name)) {
			t.Fatalf("expected file %s not found", name)
		}
	}
}

func TestFirstProvisionNoPlaintextKeyFiles(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	_, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	tlsDir := filepath.Join(dataDir, tlsSubDir)
	entries, _ := os.ReadDir(tlsDir)
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".pem" {
			t.Fatalf("plaintext PEM found: %s", e.Name())
		}
	}
}

func TestFirstProvisionIncompleteFilesFails(t *testing.T) {
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "data", tlsSubDir)
	os.MkdirAll(tlsDir, 0700)
	os.WriteFile(filepath.Join(tlsDir, caCertFile), []byte("bad"), 0600)

	_, err := Provision(filepath.Join(dir, "data"), passthroughProtector(), okTrustStore(), fixedNow(time.Now()))
	if err == nil {
		t.Fatal("should fail with incomplete material")
	}
}

func TestReloadPreservesCA(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	m1, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	fp1 := m1.CAFingerprintSHA256

	m2, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("reload Provision: %v", err)
	}
	if m2.CAFingerprintSHA256 != fp1 {
		t.Fatal("CA fingerprint changed across reload")
	}
}

func TestReloadRenewsNearExpiry(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	m1, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	fp1 := m1.CAFingerprintSHA256

	nearExpiry := now.Add(61 * 24 * time.Hour)
	m2, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(nearExpiry))
	if err != nil {
		t.Fatalf("renew Provision: %v", err)
	}
	if m2.CAFingerprintSHA256 != fp1 {
		t.Fatal("CA fingerprint changed after server renewal")
	}
	if m2.ServerCertificate.Equal(m1.ServerCertificate) {
		t.Fatal("server certificate was not renewed")
	}
	if m2.ServerCertificate.NotAfter.Before(nearExpiry.Add(29 * 24 * time.Hour)) {
		t.Fatal("renewed server cert expires too soon")
	}
}

func TestCorruptProtectedKeyFails(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	_, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	keyPath := filepath.Join(dataDir, tlsSubDir, caKeyFile)
	data, _ := os.ReadFile(keyPath)
	data[0] ^= 0xFF
	os.WriteFile(keyPath, data, 0600)

	_, err = Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err == nil {
		t.Fatal("should fail with corrupt CA key")
	}
}

func TestFakeTrustStoreFailureAbortsProvisioning(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	store := &fakeTrustStore{
		install: func([]byte) error { return fmt.Errorf("trust store unavailable") },
		remove:  func([]byte) error { return nil },
		verify:  func([]byte) (TrustState, error) { return TrustHealthy, nil },
		is:      func([32]byte) (bool, error) { return true, nil },
	}

	_, err := Provision(dataDir, passthroughProtector(), store, fixedNow(time.Now()))
	if err == nil {
		t.Fatal("should fail when TrustStore is unavailable")
	}
}

func TestReloadRejectsWrongSAN(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	if _, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now)); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	tlsDir := filepath.Join(dataDir, tlsSubDir)

	// Load the persisted CA and server key so the wrong-SAN certificate is
	// signed by the SAME persisted CA and carries the SAME persisted server key,
	// passing issuer and key validation and isolating the SAN policy.
	caCert, caKey, err := loadCA(tlsDir, passthroughProtector())
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}
	_, serverKey, err := loadServer(tlsDir, passthroughProtector())
	if err != nil {
		t.Fatalf("loadServer: %v", err)
	}

	// Build an actually-encoded server certificate with an explicitly wrong SAN.
	wrongCert := buildServerCertWithSAN(t, now, caCert, caKey, &serverKey.PublicKey, []string{"evil.local"})

	if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), wrongCert.Raw, 0600); err != nil {
		t.Fatalf("write wrong-SAN server cert: %v", err)
	}

	_, err = Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err == nil {
		t.Fatal("should reject server cert with wrong SAN")
	}
	if !strings.Contains(err.Error(), "SAN") {
		t.Fatalf("expected SAN validation error, got: %v", err)
	}
}

// buildServerCertWithSAN constructs an encoded server certificate signed by the
// given CA signer with the given DNS SANs and public key, otherwise mirroring
// the production server certificate template. It exists so the wrong-SAN
// regression test can produce an actually-encoded invalid-SAN certificate.
func buildServerCertWithSAN(t *testing.T, now time.Time, caCert *x509.Certificate, caSigner crypto.Signer, pub crypto.PublicKey, dnsNames []string) *x509.Certificate {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatalf("randomSerial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverCN, Organization: []string{serverOrg}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(serverValidity),
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caSigner)
	if err != nil {
		t.Fatalf("create wrong-SAN server certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse wrong-SAN server certificate: %v", err)
	}
	return cert
}

func TestReloadRenewsExpiredServerCert(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	m1, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	fp1 := m1.CAFingerprintSHA256

	expiredTime := now.Add(100 * 24 * time.Hour)
	m2, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(expiredTime))
	if err != nil {
		t.Fatalf("renew Provision: %v", err)
	}
	if m2.CAFingerprintSHA256 != fp1 {
		t.Fatal("CA fingerprint changed after expired server renewal")
	}
	if m2.ServerCertificate.Equal(m1.ServerCertificate) {
		t.Fatal("server certificate was not renewed")
	}
}

func TestPersistedCAWithWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	_, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	_, wrongKey, _ := generateCA(now)
	wrongKeyDER, _ := marshaledKey(wrongKey)
	p := passthroughProtector()
	wrongProtected, _ := p.Protect(wrongKeyDER)
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	atomicWrite(filepath.Join(tlsDir, caKeyFile), wrongProtected, 0600)

	_, err = Provision(dataDir, p, okTrustStore(), fixedNow(now))
	if err == nil {
		t.Fatal("should fail with wrong CA private key")
	}
}

func TestPersistedServerWithWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	_, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	caCert, caKey, _ := generateCA(now)
	_, wrongKey, _ := generateServerCert(now, caCert, caKey)
	wrongKeyDER, _ := marshaledKey(wrongKey)
	p := passthroughProtector()
	wrongProtected, _ := p.Protect(wrongKeyDER)
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	atomicWrite(filepath.Join(tlsDir, serverKeyFile), wrongProtected, 0600)

	_, err = Provision(dataDir, p, okTrustStore(), fixedNow(now))
	if err == nil {
		t.Fatal("should fail with wrong server private key")
	}
}

func TestTrustStoreReceivesCA(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	var firstInstallDER []byte
	var reloadVerifyDER []byte
	store := &fakeTrustStore{
		install: func(der []byte) error {
			firstInstallDER = append([]byte{}, der...)
			return nil
		},
		remove: func([]byte) error { return nil },
		verify: func(der []byte) (TrustState, error) {
			reloadVerifyDER = append([]byte{}, der...)
			return TrustHealthy, nil
		},
		is: func([32]byte) (bool, error) { return false, nil },
	}

	m1, err := Provision(dataDir, passthroughProtector(), store, fixedNow(now))
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	if len(firstInstallDER) == 0 {
		t.Fatal("InstallTrust was not called during first provision")
	}
	if m1.CAFingerprintSHA256 != sha256.Sum256(firstInstallDER) {
		t.Fatal("fingerprint of CA passed to trust store does not match returned material")
	}

	m2, err := Provision(dataDir, passthroughProtector(), store, fixedNow(now))
	if err != nil {
		t.Fatalf("reload Provision: %v", err)
	}
	if len(reloadVerifyDER) == 0 {
		t.Fatal("VerifyTrust was not called during reload")
	}
	if m2.CAFingerprintSHA256 != sha256.Sum256(reloadVerifyDER) {
		t.Fatal("fingerprint of CA verified during reload does not match returned material")
	}
}

// fakeMachineKeyStore returns a signer backed by an ephemeral ECDSA P-256 key.
// Used to simulate a persisted CNG key that already exists when the cert is missing.
type fakeMachineKeyStore struct {
	simulateExistingCA     bool
	simulateExistingServer bool
	caSigner               crypto.Signer
	serverSigner           crypto.Signer
}

func newFakeMachineKeyStore(existingCA, existingServer bool) fakeMachineKeyStore {
	ks := fakeMachineKeyStore{
		simulateExistingCA:     existingCA,
		simulateExistingServer: existingServer,
	}
	if existingCA {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ks.caSigner = caKey
	}
	if existingServer {
		serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ks.serverSigner = serverKey
	}
	return ks
}

func (f fakeMachineKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	if f.simulateExistingCA {
		return f.caSigner, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, nil
}

func (f fakeMachineKeyStore) LoadOrCreateServerKey() (crypto.Signer, error) {
	if f.simulateExistingServer {
		return f.serverSigner, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, nil
}

// countingKeyStore records MachineKeyStore calls so tests can prove a path
// never acquires (and therefore never creates) a key.
type countingKeyStore struct {
	inner            MachineKeyStore
	caCalls, srCalls int
}

func (c *countingKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	c.caCalls++
	return c.inner.LoadOrCreateCAKey()
}

func (c *countingKeyStore) LoadOrCreateServerKey() (crypto.Signer, error) {
	c.srCalls++
	return c.inner.LoadOrCreateServerKey()
}

// countingTrustStore counts InstallTrust calls on top of okTrustStore.
func countingTrustStore(installs *int) *fakeTrustStore {
	ts := okTrustStore()
	ts.install = func([]byte) error { *installs++; return nil }
	return ts
}

// TestProvisionPartialStateFailsClosed proves that when exactly one of the two
// certificate DERs exists, ProvisionWithKeyStore fails closed without acquiring
// a key, reissuing the CA certificate or installing trust.
func TestProvisionPartialStateFailsClosed(t *testing.T) {
	for _, missing := range []string{caCertFile, serverCertFile} {
		t.Run("missing "+missing, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
			ks := newFakeMachineKeyStore(true, true)
			if _, err := ProvisionWithKeyStore(dataDir, ks, okTrustStore(), fixedNow(now)); err != nil {
				t.Fatalf("first provision: %v", err)
			}
			tlsDir := filepath.Join(dataDir, tlsSubDir)
			kept := caCertFile
			if missing == caCertFile {
				kept = serverCertFile
			}
			keptBytes, _ := os.ReadFile(filepath.Join(tlsDir, kept))
			os.Remove(filepath.Join(tlsDir, missing))

			counting := &countingKeyStore{inner: ks}
			installs := 0
			_, err := ProvisionWithKeyStore(dataDir, counting, countingTrustStore(&installs), fixedNow(now))
			if !errors.Is(err, ErrInconsistentMachineState) {
				t.Fatalf("err = %v, want ErrInconsistentMachineState", err)
			}
			if counting.caCalls+counting.srCalls != 0 || installs != 0 {
				t.Fatalf("partial state acquired keys (%d/%d) or installed trust (%d)", counting.caCalls, counting.srCalls, installs)
			}
			after, _ := os.ReadFile(filepath.Join(tlsDir, kept))
			if !bytes.Equal(after, keptBytes) || fileExists(filepath.Join(tlsDir, missing)) {
				t.Fatal("partial state must be left exactly as found")
			}
		})
	}
}

// TestProvisionStatAccessErrorFailsClosed proves that a certificate DER whose
// presence cannot be determined is not treated as absent by either the
// pre-check or ProvisionWithKeyStore.
func TestProvisionStatAccessErrorFailsClosed(t *testing.T) {
	saved := osFS
	t.Cleanup(func() { osFS = saved })
	osFS.stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }

	dataDir := filepath.Join(t.TempDir(), "data")
	counting := &countingKeyStore{inner: newFakeMachineKeyStore(false, false)}
	installs := 0
	_, err := ProvisionWithKeyStore(dataDir, counting, countingTrustStore(&installs), fixedNow(time.Now()))
	if !errors.Is(err, ErrInconsistentMachineState) || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("err = %v, want ErrInconsistentMachineState carrying the access error", err)
	}
	if counting.caCalls+counting.srCalls != 0 || installs != 0 {
		t.Fatal("an undeterminable DER must not start a first install")
	}

	probe := &precheckProbe{}
	isPriv, _ := privileged(true, nil)
	if err := provisionPreCheck(filepath.Join(dataDir, tlsSubDir), precheckCAKey, probe.probe, isPriv); !errors.Is(err, ErrInconsistentMachineState) {
		t.Fatalf("pre-check err = %v, want ErrInconsistentMachineState", err)
	}
	if probe.calls != 0 {
		t.Fatal("pre-check must fail before probing keys")
	}
}

// TestProvisionWithKeyStoreExistingStateNeverRenews proves the existing-state provisioning
// policy: a still-valid leaf inside the renewal window is returned as verified
// Material with a nil error, an expired leaf fails with ErrRenewalDue and
// ErrCertificateNotValidNow, and neither case writes certificates, stages a
// candidate or installs trust.
func TestProvisionWithKeyStoreExistingStateNeverRenews(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	ks := &closeTrackingKeyStore{caSigner: newFakeCloseSigner(), serverSigner: newFakeCloseSigner()}
	first, err := ProvisionWithKeyStore(dataDir, ks, okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	before, _ := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	assertUnchanged := func(t *testing.T, installs int) {
		t.Helper()
		after, _ := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
		if !bytes.Equal(after, before) || fileExists(filepath.Join(tlsDir, pendingServerCertFile)) || installs != 0 {
			t.Fatal("existing-state provisioning must not write certificates, stage a candidate or install trust")
		}
	}
	reset := func() {
		ks.caSigner.closed, ks.serverSigner.closed = false, false
	}

	t.Run("valid within renewal window", func(t *testing.T) {
		reset()
		installs := 0
		m, err := ProvisionWithKeyStore(dataDir, ks, countingTrustStore(&installs), fixedNow(now.Add(61*24*time.Hour)))
		if err != nil {
			t.Fatalf("err = %v, want nil (verified, not renewed)", err)
		}
		if !m.ServerCertificate.Equal(first.ServerCertificate) {
			t.Fatal("provisioning must return the existing, unrenewed certificate")
		}
		if !ks.caSigner.closed || ks.serverSigner.closed {
			t.Fatal("CA signer must be released and the server signer transferred to the caller")
		}
		assertUnchanged(t, installs)
	})
	t.Run("expired", func(t *testing.T) {
		reset()
		installs := 0
		m, err := ProvisionWithKeyStore(dataDir, ks, countingTrustStore(&installs), fixedNow(now.Add(91*24*time.Hour)))
		if !errors.Is(err, ErrRenewalDue) || !errors.Is(err, ErrCertificateNotValidNow) {
			t.Fatalf("err = %v, want ErrRenewalDue and ErrCertificateNotValidNow", err)
		}
		if m.ServerCertificate != nil || m.Certificate.PrivateKey != nil {
			t.Fatal("a failure must return a zero Material")
		}
		if !ks.caSigner.closed || !ks.serverSigner.closed {
			t.Fatal("both signers must be released on failure")
		}
		assertUnchanged(t, installs)
	})
	t.Run("trust not healthy", func(t *testing.T) {
		reset()
		installs := 0
		ts := countingTrustStore(&installs)
		ts.verify = func([]byte) (TrustState, error) { return TrustAbsent, nil }
		if _, err := ProvisionWithKeyStore(dataDir, ks, ts, fixedNow(now.Add(61*24*time.Hour))); !errors.Is(err, ErrTrustNotHealthy) {
			t.Fatalf("err = %v, want ErrTrustNotHealthy", err)
		}
		if !ks.caSigner.closed || !ks.serverSigner.closed {
			t.Fatal("both signers must be released on failure")
		}
		assertUnchanged(t, installs)
	})
}

// TestProvisionStateClassification proves the production state matrix: only a
// true first install (nothing present) and a complete state (both certificate
// DERs and both persisted keys) are allowed to proceed; every partial state is
// classified inconsistent so ProvisionMachine fails closed instead of silently
// regenerating the CA or creating replacement keys.
func TestProvisionStateClassification(t *testing.T) {
	cases := []struct {
		name                               string
		caDER, serverDER, caKey, serverKey bool
		wantInconsistent                   bool
	}{
		// True first install: nothing present.
		{"first install", false, false, false, false, false},
		// Complete state: both DERs and both keys.
		{"complete", true, true, true, true, false},
		// Both DERs present but a key is missing → inconsistent.
		{"complete DER CA key missing", true, true, false, true, true},
		{"complete DER server key missing", true, true, true, false, true},
		{"complete DER both keys missing", true, true, false, false, true},
		// Partial DER → inconsistent regardless of keys.
		{"ca DER only", true, false, false, false, true},
		{"ca DER only with keys", true, false, true, true, true},
		{"server DER only", false, true, false, false, true},
		{"server DER only with keys", false, true, true, true, true},
		// Orphan key (no certificate material) → inconsistent.
		{"ca key orphan", false, false, true, false, true},
		{"server key orphan", false, false, false, true, true},
		{"both keys orphan", false, false, true, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := provisionStateInconsistent(tc.caDER, tc.serverDER, tc.caKey, tc.serverKey)
			if got != tc.wantInconsistent {
				t.Fatalf("provisionStateInconsistent(caDER=%v serverDER=%v caKey=%v serverKey=%v) = %v, want %v",
					tc.caDER, tc.serverDER, tc.caKey, tc.serverKey, got, tc.wantInconsistent)
			}
		})
	}
}

// TestReloadRejectsCorruptCADER proves that a corrupt CA certificate DER on the
// production path fails closed without silently regenerating a new CA identity.
func TestReloadRejectsCorruptCADER(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	ks := newFakeMachineKeyStore(true, true)
	if _, err := ProvisionWithKeyStore(dataDir, ks, okTrustStore(), fixedNow(now)); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	// Corrupt the on-disk CA certificate DER.
	caPath := filepath.Join(dataDir, tlsSubDir, caCertFile)
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("corrupt CA DER: %v", err)
	}

	// Re-provision with the same keys must fail closed and must not overwrite
	// the corrupt DER with a freshly regenerated CA.
	ks2 := newFakeMachineKeyStore(true, true)
	ks2.caSigner = ks.caSigner
	ks2.serverSigner = ks.serverSigner
	if _, err := ProvisionWithKeyStore(dataDir, ks2, okTrustStore(), fixedNow(now)); err == nil {
		t.Fatal("expected re-provision with corrupt CA DER to fail closed")
	}

	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA DER after failed re-provision: %v", err)
	}
	if string(got) != "not a certificate" {
		t.Fatalf("CA DER was silently regenerated: %q", got)
	}
}

// ---- LTL-001: existing-state provisioning never installs trust ----

// TestReloadWithoutRepairDoesNotInstallTrust proves that existing-state
// provisioning fails closed on a missing trust anchor and never
// installs trust.
func TestReloadWithoutRepairDoesNotInstallTrust(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	installCount := 0
	store := &fakeTrustStore{
		install: func([]byte) error { installCount++; return nil },
		remove:  func([]byte) error { return nil },
		verify:  func([]byte) (TrustState, error) { return TrustAbsent, nil },
		is:      func([32]byte) (bool, error) { return false, nil },
	}

	ks1 := newFakeMachineKeyStore(true, true)
	if _, err := ProvisionWithKeyStore(dataDir, ks1, store, fixedNow(now)); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	firstInstallCount := installCount

	ks2 := newFakeMachineKeyStore(true, true)
	ks2.caSigner = ks1.caSigner
	ks2.serverSigner = ks1.serverSigner
	if _, err := ProvisionWithKeyStore(dataDir, ks2, store, fixedNow(now)); err == nil {
		t.Fatal("expected reload with missing trust to fail closed")
	}
	if installCount != firstInstallCount {
		t.Fatal("reload-only path must not install trust")
	}
}

// ---- LTL-002: reject existing state under an invalid CA lifetime ----

// TestExistingStateProvisioningRejectsExpiredCA proves existing-state
// provisioning rejects a CA that has expired rather than returning material
// that clients would reject during chain validation.
func TestExistingStateProvisioningRejectsExpiredCA(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	ks1 := newFakeMachineKeyStore(true, true)
	if _, err := ProvisionWithKeyStore(dataDir, ks1, okTrustStore(), fixedNow(now)); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	// Advance past CA expiry: the server is also expired, forcing renewal.
	expiredTime := now.Add(caValidity).Add(24 * time.Hour)
	ks2 := newFakeMachineKeyStore(true, true)
	ks2.caSigner = ks1.caSigner
	ks2.serverSigner = ks1.serverSigner

	if _, err := ProvisionWithKeyStore(dataDir, ks2, okTrustStore(), fixedNow(expiredTime)); err == nil {
		t.Fatal("expected renewal to reject an expired CA")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected clear expired-CA error, got: %v", err)
	}
}

// TestExistingStateProvisioningRejectsNotYetValidCA proves existing-state
// provisioning rejects a CA whose NotBefore is in the future relative to now.
// It exercises ProvisionWithKeyStore (not just validateCA) and verifies no
// replacement CA identity is silently generated.
func TestExistingStateProvisioningRejectsNotYetValidCA(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	renewTime := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	caSigner := newFakeCloseSigner()
	caCert := buildNotYetValidCA(t, renewTime, caSigner)

	serverSigner := newFakeCloseSigner()
	serverCert := buildExpiredServerCertSignedBy(t, renewTime, caCert, caSigner, &serverSigner.key.PublicKey)

	if err := atomicWrite(filepath.Join(tlsDir, caCertFile), caCert.Raw, 0600); err != nil {
		t.Fatalf("write CA DER: %v", err)
	}
	if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), serverCert.Raw, 0600); err != nil {
		t.Fatalf("write server DER: %v", err)
	}

	ks := fakeMachineKeyStore{
		simulateExistingCA:     true,
		simulateExistingServer: true,
		caSigner:               caSigner,
		serverSigner:           serverSigner,
	}

	_, err := ProvisionWithKeyStore(dataDir, ks, okTrustStore(), fixedNow(renewTime))
	if err == nil {
		t.Fatal("expected renewal to reject a not-yet-valid CA")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected clear not-yet-valid-CA error, got: %v", err)
	}

	got, readErr := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if readErr != nil {
		t.Fatalf("read CA DER: %v", readErr)
	}
	if sha256.Sum256(got) != sha256.Sum256(caCert.Raw) {
		t.Fatal("CA DER was silently replaced during failed renewal")
	}
}

// buildNotYetValidCA constructs a self-signed CA certificate whose NotBefore is
// in the future relative to now (so it is not yet valid at now).
func buildNotYetValidCA(t *testing.T, now time.Time, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatalf("randomSerial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCN, Organization: []string{caOrg}},
		NotBefore:             now.Add(time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create not-yet-valid CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse not-yet-valid CA: %v", err)
	}
	return cert
}

// buildExpiredServerCertSignedBy constructs a server certificate signed by the
// given CA whose NotAfter is in the past relative to now (so it is expired),
// with production-matching SANs.
func buildExpiredServerCertSignedBy(t *testing.T, now time.Time, caCert *x509.Certificate, caSigner crypto.Signer, serverPub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatalf("randomSerial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverCN, Organization: []string{serverOrg}},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, serverPub, caSigner)
	if err != nil {
		t.Fatalf("create expired server certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse expired server certificate: %v", err)
	}
	return cert
}
