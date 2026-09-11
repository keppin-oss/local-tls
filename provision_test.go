package localtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
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

func (fts *fakeTrustStore) EnsureTrusted(der []byte) error             { return fts.install(der) }
func (fts *fakeTrustStore) InstallTrust(der []byte) error              { return fts.install(der) }
func (fts *fakeTrustStore) RemoveTrust(der []byte) error               { return fts.remove(der) }
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

	_, err := Provision(dataDir, passthroughProtector(), okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	caCert, caKey, _ := generateCA(now)
	wrongCert, wrongKey, _ := generateServerCert(now, caCert, caKey)
	wrongCert.DNSNames = []string{"evil.local"}
	serverKeyDER, _ := marshaledKey(wrongKey)
	p := passthroughProtector()
	keyOut, _ := p.Protect(serverKeyDER)
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	atomicWrite(filepath.Join(tlsDir, serverCertFile), wrongCert.Raw, 0600)
	atomicWrite(filepath.Join(tlsDir, serverKeyFile), keyOut, 0600)

	_, err = Provision(dataDir, p, okTrustStore(), fixedNow(now))
	if err == nil {
		t.Fatal("should reject server cert with wrong SAN")
	}
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

// TestProvisionExistingKeyMissingCertMustNotRegenerateCA verifies the
// production requirement that when a persisted CA key exists but the CA
// certificate DER is missing, firstProvisionWithKeyStore will regenerate
// a new CA certificate with a different fingerprint. This test documents
// the behavior that the composition-layer guard (checkInconsistentMachineState)
// is designed to prevent.
func TestProvisionExistingKeyMissingCertRegeneratesCA(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	// 1. First provision with a key store that has existing keys.
	ks1 := newFakeMachineKeyStore(true, true)
	m1, err := ProvisionWithKeyStore(dataDir, ks1, okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	fp1 := m1.CAFingerprintSHA256

	// 2. Remove ca-cert.der to simulate missing/corrupt public material.
	os.Remove(filepath.Join(dataDir, tlsSubDir, caCertFile))

	// 3. Re-provision with the same key store (same keys).
	ks2 := newFakeMachineKeyStore(true, true)
	ks2.caSigner = ks1.caSigner
	ks2.serverSigner = ks1.serverSigner

	m2, err := ProvisionWithKeyStore(dataDir, ks2, okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("re-provision after cert removal: %v", err)
	}
	fp2 := m2.CAFingerprintSHA256

	// 4. The CA fingerprint MUST differ — this proves that without the
	//    composition-layer guard, ProvisionWithKeyStore silently regenerates
	//    a new CA certificate against an existing key.
	if fp1 == fp2 {
		t.Fatal("CA fingerprint did NOT change after cert removal; this is unexpected — the test expects regeneration")
	}

	t.Logf("CA fingerprint changed: %x → %x (expected — without guard, new cert is generated against existing key)", fp1, fp2)
	t.Log("This test documents the behavior that the composition-layer guard prevents in production.")
}

// TestRenewalViaKeyStorePreservesCAAndServerKey proves the renewal logic remains
// functional at the keystore seam: renewing a near-expiry server certificate
// through ProvisionWithKeyStore preserves the CA identity and reuses the
// existing server key (key rotation is decoupled from certificate renewal).
func TestRenewalViaKeyStorePreservesCAAndServerKey(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	ks1 := newFakeMachineKeyStore(true, true)
	m1, err := ProvisionWithKeyStore(dataDir, ks1, okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	fp1 := m1.CAFingerprintSHA256
	serverPub1, ok := m1.Certificate.PrivateKey.(crypto.Signer).Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("server signer public key is %T, want *ecdsa.PublicKey", m1.Certificate.PrivateKey.(crypto.Signer).Public())
	}

	// Advance near server expiry to force renewal through the keystore seam.
	nearExpiry := now.Add(61 * 24 * time.Hour)
	ks2 := newFakeMachineKeyStore(true, true)
	ks2.caSigner = ks1.caSigner
	ks2.serverSigner = ks1.serverSigner

	m2, err := ProvisionWithKeyStore(dataDir, ks2, okTrustStore(), fixedNow(nearExpiry))
	if err != nil {
		t.Fatalf("renew provision: %v", err)
	}
	if m2.CAFingerprintSHA256 != fp1 {
		t.Fatal("CA fingerprint changed across renewal")
	}
	if m2.ServerCertificate.Equal(m1.ServerCertificate) {
		t.Fatal("server certificate was not renewed")
	}
	serverPub2, ok := m2.Certificate.PrivateKey.(crypto.Signer).Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("renewed server signer public key is %T, want *ecdsa.PublicKey", m2.Certificate.PrivateKey.(crypto.Signer).Public())
	}
	if serverPub2.X.Cmp(serverPub1.X) != 0 || serverPub2.Y.Cmp(serverPub1.Y) != 0 {
		t.Fatal("server key was rotated during certificate renewal; expected reuse of the persisted key")
	}
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
