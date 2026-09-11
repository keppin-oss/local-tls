//go:build windows

package localtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/keppin-oss/local-tls/internal/identity"
	"golang.org/x/sys/windows"
)

// TestTrustStoreInstallAndVerify tests the Windows trust adapter with
// an ephemeral certificate. On a machine without elevation, InstallTrust
// and RemoveTrust are expected to fail with an access-denied error.
// VerifyTrust and IsTrustedSHA256 should work non-elevated.
func TestTrustStoreInstallAndVerify(t *testing.T) {
	store, err := platformTrustStore()
	if err != nil {
		t.Skipf("platform trust store not available: %v", err)
	}
	wts, ok := store.(*windowsTrustStore)
	if !ok {
		t.Skip("not a windowsTrustStore; skipping Windows-specific test")
	}

	cert := generateTestCACert(t)
	fp := ComputeSHA256Fingerprint(cert.Raw)

	state, err := wts.VerifyTrust(cert.Raw)
	if err != nil {
		t.Fatalf("VerifyTrust (should work non-elevated): %v", err)
	}
	if state != TrustAbsent {
		t.Logf("Test CA already present in LocalMachine\\Root (state=%s); may be leftover", state)
	}

	found, err := wts.IsTrustedSHA256(fp)
	if err != nil {
		t.Fatalf("IsTrustedSHA256: %v", err)
	}
	if found {
		t.Log("Test CA already trusted — continuing")
	}

	err = wts.InstallTrust(cert.Raw)
	if err != nil {
		t.Logf("InstallTrust failed as non-admin (expected): %v", err)
		t.Log("Skipping elevated-only portions: not running as administrator")
		return
	}
	t.Log("InstallTrust succeeded (running elevated)")

	state, err = wts.VerifyTrust(cert.Raw)
	if err != nil {
		t.Fatalf("VerifyTrust after install: %v", err)
	}
	if state != TrustHealthy {
		t.Fatalf("expected TrustHealthy after install, got %s", state)
	}

	// Idempotency: second install must not fail or duplicate.
	err = wts.InstallTrust(cert.Raw)
	if err != nil {
		t.Fatalf("InstallTrust (idempotent) failed: %v", err)
	}

	found, err = wts.IsTrustedSHA256(fp)
	if err != nil {
		t.Fatalf("IsTrustedSHA256 after install: %v", err)
	}
	if !found {
		t.Fatal("IsTrustedSHA256 returned false after install")
	}

	// Cleanup: remove the test cert.
	err = wts.RemoveTrust(cert.Raw)
	if err != nil {
		t.Fatalf("RemoveTrust failed: %v", err)
	}

	state, err = wts.VerifyTrust(cert.Raw)
	if err != nil {
		t.Fatalf("VerifyTrust after remove: %v", err)
	}
	if state != TrustAbsent {
		t.Fatalf("expected TrustAbsent after removal, got %s", state)
	}

	found, err = wts.IsTrustedSHA256(fp)
	if err != nil {
		t.Fatalf("IsTrustedSHA256 after remove: %v", err)
	}
	if found {
		t.Fatal("IsTrustedSHA256 returned true after removal")
	}
}

// TestTrustStoreConflictingCert tests CN-based conflict detection.
func TestTrustStoreConflictingCert(t *testing.T) {
	store, err := platformTrustStore()
	if err != nil {
		t.Skipf("platform trust store not available: %v", err)
	}
	wts, ok := store.(*windowsTrustStore)
	if !ok {
		t.Skip("not a windowsTrustStore")
	}

	cert1 := generateTestCACert(t)
	cert2 := generateTestCACert(t)

	fp1 := ComputeSHA256Fingerprint(cert1.Raw)
	fp2 := ComputeSHA256Fingerprint(cert2.Raw)
	if fp1 == fp2 {
		t.Fatal("two generated certs have same fingerprint; test invalid")
	}

	err = wts.InstallTrust(cert1.Raw)
	if err != nil {
		t.Skipf("InstallTrust failed (not elevated): %v — skipping conflict test", err)
	}
	defer func() { _ = wts.RemoveTrust(cert1.Raw) }()

	state, err := wts.VerifyTrust(cert2.Raw)
	if err != nil {
		t.Fatalf("VerifyTrust for cert2: %v", err)
	}
	if state != TrustConflict {
		t.Fatalf("expected TrustConflict, got %s", state)
	}

	if err := wts.RemoveTrust(cert1.Raw); err != nil {
		t.Fatalf("RemoveTrust cleanup: %v", err)
	}

	state, err = wts.VerifyTrust(cert2.Raw)
	if err != nil {
		t.Fatalf("VerifyTrust for cert2 after cleanup: %v", err)
	}
	if state != TrustAbsent {
		t.Fatalf("expected TrustAbsent after cleanup, got %s", state)
	}
}

// TestFindCertByCNMemoryStore verifies the same-CN lookup without requiring
// Administrator elevation, by exercising findCertByCN against an in-memory
// certificate store. This guards the CERT_FIND_SUBJECT_STR_A find-type and
// string-encoding correctness that TestTrustStoreConflictingCert relies on.
func TestFindCertByCNMemoryStore(t *testing.T) {
	cert := generateTestCACert(t)

	certCtx, err := windows.CertCreateCertificateContext(
		x509AsnEncoding|pkcs7AsnEncoding,
		&cert.Raw[0],
		uint32(len(cert.Raw)),
	)
	if err != nil {
		t.Fatalf("CertCreateCertificateContext: %v", err)
	}
	defer windows.CertFreeCertificateContext(certCtx)

	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_MEMORY,
		0, 0, 0, 0,
	)
	if err != nil {
		t.Fatalf("CertOpenStore(memory): %v", err)
	}
	defer windows.CertCloseStore(store, 0)

	if err := windows.CertAddCertificateContextToStore(store, certCtx, windows.CERT_STORE_ADD_NEW, nil); err != nil {
		t.Fatalf("CertAddCertificateContextToStore: %v", err)
	}

	cn, err := getCertCommonName(certCtx)
	if err != nil {
		t.Fatalf("getCertCommonName: %v", err)
	}
	if cn == "" {
		t.Fatal("empty CN from test certificate")
	}

	found, err := findCertByCN(store, cn)
	if err != nil {
		t.Fatalf("findCertByCN: %v", err)
	}
	if found == nil {
		t.Fatalf("findCertByCN(%q) did not find the installed certificate", cn)
	}
	windows.CertFreeCertificateContext(found)
}

func TestTrustStoreEmptyDER(t *testing.T) {
	store, err := platformTrustStore()
	if err != nil {
		t.Skipf("platform trust store not available: %v", err)
	}
	wts, ok := store.(*windowsTrustStore)
	if !ok {
		t.Skip("not a windowsTrustStore")
	}
	if err := wts.InstallTrust(nil); err == nil {
		t.Fatal("InstallTrust(nil) should fail")
	}
	if err := wts.InstallTrust([]byte{}); err == nil {
		t.Fatal("InstallTrust([]) should fail")
	}
	if _, err := wts.VerifyTrust(nil); err == nil {
		t.Fatal("VerifyTrust(nil) should return error state")
	}
	if _, err := wts.VerifyTrust([]byte{}); err == nil {
		t.Fatal("VerifyTrust([]) should return error state")
	}
	if err := wts.RemoveTrust(nil); err == nil {
		t.Fatal("RemoveTrust(nil) should fail")
	}
	if err := wts.RemoveTrust([]byte{}); err == nil {
		t.Fatal("RemoveTrust([]) should fail")
	}
}

func TestRemoveNonExistent(t *testing.T) {
	store, err := platformTrustStore()
	if err != nil {
		t.Skipf("platform trust store not available: %v", err)
	}
	wts, ok := store.(*windowsTrustStore)
	if !ok {
		t.Skip("not a windowsTrustStore")
	}
	cert := generateTestCACert(t)
	fp := ComputeSHA256Fingerprint(cert.Raw)
	found, _ := wts.IsTrustedSHA256(fp)
	if found {
		_ = wts.RemoveTrust(cert.Raw)
	}
	err = wts.RemoveTrust(cert.Raw)
	if err == nil {
		t.Fatal("RemoveTrust should fail for cert not in store")
	}
	t.Logf("RemoveTrust(non-existent) correctly failed: %v", err)
}

func TestPlatformTrustStoreReturnsStore(t *testing.T) {
	store, err := PlatformTrustStore()
	if err != nil {
		t.Fatalf("PlatformTrustStore: %v", err)
	}
	if store == nil {
		t.Fatal("PlatformTrustStore returned nil")
	}
	if _, ok := store.(TrustProvisioner); !ok {
		t.Fatal("returned store does not implement TrustProvisioner")
	}
	if _, ok := store.(TrustVerifier); !ok {
		t.Fatal("returned store does not implement TrustVerifier")
	}
}

// generateTestCACert creates a self-signed CA cert with a fixed CN for testing.
func generateTestCACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   identity.ProductName + " Test Trust CA",
			Organization: []string{identity.CertOrganization},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestCertDERHashStability proves SHA-256 fingerprint stability.
func TestCertDERHashStability(t *testing.T) {
	cert := generateTestCACert(t)
	fpDirect := sha256.Sum256(cert.Raw)
	fpSlice := sha256.Sum256(append([]byte{}, cert.Raw...))
	if fpDirect != fpSlice {
		t.Fatalf("SHA-256 mismatch: direct=%x slice=%x", fpDirect, fpSlice)
	}
}

// TestDeleteCertificateFromStoreOwnership exercises the removal path's
// ownership contract on an in-memory store (no LocalMachine\Root mutation, no
// elevation): CertDeleteCertificateFromStore already frees the found
// CERT_CONTEXT, so the removal helper must free the context exactly once and
// the certificate must be gone from the store afterward. This locks the fix that
// removed the redundant CertFreeCertificateContext after CertDeleteCertificateFromStore.
func TestDeleteCertificateFromStoreOwnership(t *testing.T) {
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("CertOpenStore(memory): %v", err)
	}
	defer windows.CertCloseStore(store, 0)

	cert := generateTestCACert(t)
	fp := sha256.Sum256(cert.Raw)

	certCtx, err := windows.CertCreateCertificateContext(
		x509AsnEncoding|pkcs7AsnEncoding,
		&cert.Raw[0],
		uint32(len(cert.Raw)),
	)
	if err != nil {
		t.Fatalf("CertCreateCertificateContext: %v", err)
	}
	if err := windows.CertAddCertificateContextToStore(store, certCtx, windows.CERT_STORE_ADD_NEW, nil); err != nil {
		windows.CertFreeCertificateContext(certCtx)
		t.Fatalf("CertAddCertificateContextToStore: %v", err)
	}
	// The caller's reference is no longer needed; the store keeps its own copy.
	windows.CertFreeCertificateContext(certCtx)

	// Find the exact context through the same helper the removal paths use.
	existing, err := findCertBySHA256(store, fp)
	if err != nil {
		t.Fatalf("findCertBySHA256: %v", err)
	}
	if existing == nil {
		t.Fatal("certificate not found in memory store")
	}

	// The removal helper takes ownership of the context and frees it (via
	// CertDeleteCertificateFromStore); the caller must not free it again.
	if err := deleteCertificateFromStore(existing); err != nil {
		t.Fatalf("deleteCertificateFromStore: %v", err)
	}

	// The certificate must no longer be present in the store.
	again, err := findCertBySHA256(store, fp)
	if err != nil {
		t.Fatalf("findCertBySHA256 after delete: %v", err)
	}
	if again != nil {
		windows.CertFreeCertificateContext(again)
		t.Fatal("certificate still present in memory store after delete")
	}
}
