package localtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"
)

// fakeCloseSigner is a crypto.Signer backed by an in-memory ECDSA P-256 key
// that also implements interface{ Close() error }, modeling the production CNG
// signer's public lifecycle without touching machine state. It records whether
// and how many times it was closed.
type fakeCloseSigner struct {
	key        *ecdsa.PrivateKey
	closed     bool
	closeCount int
	closeErr   error
}

func newFakeCloseSigner() *fakeCloseSigner {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &fakeCloseSigner{key: key}
}

func (f *fakeCloseSigner) Public() crypto.PublicKey { return &f.key.PublicKey }

func (f *fakeCloseSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return f.key.Sign(r, digest, opts)
}

func (f *fakeCloseSigner) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	if !f.closed {
		f.closed = true
		f.closeCount++
	}
	return nil
}

// closeTrackingKeyStore implements MachineKeyStore and MachineKeyDeleter using
// fakeCloseSigners, recording any key deletions so tests can prove Close never
// triggers deletion.
type closeTrackingKeyStore struct {
	caSigner     *fakeCloseSigner
	serverSigner *fakeCloseSigner
	deleteCA     int
	deleteServer int
}

func (ks *closeTrackingKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	return ks.caSigner, nil
}

func (ks *closeTrackingKeyStore) LoadOrCreateServerKey() (crypto.Signer, error) {
	return ks.serverSigner, nil
}

func (ks *closeTrackingKeyStore) DeleteCAKey() error {
	ks.deleteCA++
	return nil
}

func (ks *closeTrackingKeyStore) DeleteServerKey() error {
	ks.deleteServer++
	return nil
}

// recordingTrustStore counts trust mutations so tests can prove Close never
// triggers trust removal.
type recordingTrustStore struct {
	removeCount int
}

func (r *recordingTrustStore) InstallTrust(der []byte) error { return nil }
func (r *recordingTrustStore) RemoveTrust(der []byte) error {
	r.removeCount++
	return nil
}
func (r *recordingTrustStore) RemoveTrustBySHA256(fp [32]byte) error {
	r.removeCount++
	return nil
}
func (r *recordingTrustStore) VerifyTrust(der []byte) (TrustState, error) {
	return TrustHealthy, nil
}
func (r *recordingTrustStore) IsTrustedSHA256(fp [32]byte) (bool, error) { return true, nil }
func (r *recordingTrustStore) EnsureTrusted(der []byte) error            { return nil }

func TestMaterialCloseReleasesServingSigner(t *testing.T) {
	ks := &closeTrackingKeyStore{
		caSigner:     newFakeCloseSigner(),
		serverSigner: newFakeCloseSigner(),
	}
	trust := &recordingTrustStore{}
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	material, err := ProvisionWithKeyStore(t.TempDir(), ks, trust, fixedNow(now))
	if err != nil {
		t.Fatalf("ProvisionWithKeyStore: %v", err)
	}

	// CA signer is transient: closed internally, exactly once.
	if !ks.caSigner.closed || ks.caSigner.closeCount != 1 {
		t.Fatalf("CA signer closed=%v count=%d, want closed once", ks.caSigner.closed, ks.caSigner.closeCount)
	}
	// Server signer is transferred: still open before Material.Close.
	if ks.serverSigner.closed {
		t.Fatal("server signer must not be closed before Material.Close")
	}
	if material.Certificate.PrivateKey != ks.serverSigner {
		t.Fatalf("Material.Certificate.PrivateKey = %T, want server signer", material.Certificate.PrivateKey)
	}

	if err := material.Close(); err != nil {
		t.Fatalf("Material.Close: %v", err)
	}
	if !ks.serverSigner.closed || ks.serverSigner.closeCount != 1 {
		t.Fatalf("server signer closed=%v count=%d, want closed once", ks.serverSigner.closed, ks.serverSigner.closeCount)
	}

	// Close must not delete keys or mutate trust.
	if ks.deleteCA != 0 || ks.deleteServer != 0 {
		t.Fatalf("Material.Close deleted keys (ca=%d server=%d)", ks.deleteCA, ks.deleteServer)
	}
	if trust.removeCount != 0 {
		t.Fatalf("Material.Close removed trust %d times", trust.removeCount)
	}
}

func TestMaterialCloseIsIdempotent(t *testing.T) {
	material := Material{
		Certificate: tlsCertFromSigner(&x509.Certificate{}, newFakeCloseSigner()),
	}
	if err := material.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := material.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	s := material.Certificate.PrivateKey.(*fakeCloseSigner)
	if s.closeCount != 1 {
		t.Fatalf("closeCount = %d, want 1 (idempotent)", s.closeCount)
	}
}

func TestMaterialCloseSurfacesError(t *testing.T) {
	want := errors.New("close failed")
	material := Material{
		Certificate: tlsCertFromSigner(&x509.Certificate{}, &fakeCloseSigner{key: newFakeCloseSigner().key, closeErr: want}),
	}
	if err := material.Close(); !errors.Is(err, want) {
		t.Fatalf("Material.Close = %v, want %v", err, want)
	}
}

func TestMaterialCloseNoopForNonClosableSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	material := Material{
		Certificate: tlsCertFromMaterial(&x509.Certificate{}, key),
	}
	if err := material.Close(); err != nil {
		t.Fatalf("Material.Close = %v, want nil (non-closable signer is a no-op)", err)
	}
}

func TestMaterialCloseNilReceiver(t *testing.T) {
	var m *Material
	if err := m.Close(); err != nil {
		t.Fatalf("nil Material.Close = %v, want nil", err)
	}
}

func TestProvisionFailureClosesBothSigners(t *testing.T) {
	ks := &closeTrackingKeyStore{
		caSigner:     newFakeCloseSigner(),
		serverSigner: newFakeCloseSigner(),
	}
	installErr := errors.New("trust store unavailable")
	trust := &fakeTrustStore{
		install: func([]byte) error { return installErr },
		remove:  func([]byte) error { return nil },
		verify:  func([]byte) (TrustState, error) { return TrustHealthy, nil },
		is:      func([32]byte) (bool, error) { return true, nil },
	}

	_, err := ProvisionWithKeyStore(t.TempDir(), ks, trust, fixedNow(time.Now()))
	if err == nil {
		t.Fatal("expected provisioning to fail")
	}
	if !ks.caSigner.closed {
		t.Fatal("CA signer must be closed on construction failure")
	}
	if !ks.serverSigner.closed {
		t.Fatal("server signer must be closed on construction failure")
	}
}

func TestReloadClosesCASigner(t *testing.T) {
	ks := &closeTrackingKeyStore{
		caSigner:     newFakeCloseSigner(),
		serverSigner: newFakeCloseSigner(),
	}
	trust := &recordingTrustStore{}
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	dataDir := t.TempDir()

	if _, err := ProvisionWithKeyStore(dataDir, ks, trust, fixedNow(now)); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if !ks.caSigner.closed {
		t.Fatal("first provision should close CA signer")
	}

	// Reset close state and re-provision: the reload path must also close the
	// CA signer while leaving the server signer open.
	ks.caSigner.closed = false
	ks.caSigner.closeCount = 0
	ks.serverSigner.closed = false
	ks.serverSigner.closeCount = 0

	if _, err := ProvisionWithKeyStore(dataDir, ks, trust, fixedNow(now)); err != nil {
		t.Fatalf("reload provision: %v", err)
	}
	if !ks.caSigner.closed || ks.caSigner.closeCount != 1 {
		t.Fatalf("reload CA signer closed=%v count=%d, want closed once", ks.caSigner.closed, ks.caSigner.closeCount)
	}
	if ks.serverSigner.closed {
		t.Fatal("reload must not close the server signer")
	}
}
