//go:build windows

package localtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"testing"
	"time"
	"unsafe"

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

// TestDeleteCertificateFromStoreOwnership exercises the removal ownership
// contract on an in-memory store (no LocalMachine\Root mutation, no
// elevation): the context found by findCertBySHA256 is handed to
// deleteCertificateFromStore, which frees it, and the certificate is gone from
// the store afterward. A separately duplicated reference held by the test is
// unaffected by the delete and is released by the test exactly once. This
// does not detect a double free by itself; TestRemoveTrustPathsDoNotFreeAfterDelete
// locks the call structure of the removal paths.
func TestDeleteCertificateFromStoreOwnership(t *testing.T) {
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("CertOpenStore(memory): %v", err)
	}
	defer windows.CertCloseStore(store, 0)

	cert := generateTestCACert(t)
	fp := sha256.Sum256(cert.Raw)

	certCtx, err := windows.CertCreateCertificateContext(x509AsnEncoding|pkcs7AsnEncoding, &cert.Raw[0], uint32(len(cert.Raw)))
	if err != nil {
		t.Fatalf("CertCreateCertificateContext: %v", err)
	}
	if err := windows.CertAddCertificateContextToStore(store, certCtx, windows.CERT_STORE_ADD_NEW, nil); err != nil {
		windows.CertFreeCertificateContext(certCtx)
		t.Fatalf("CertAddCertificateContextToStore: %v", err)
	}
	// The store keeps its own copy; the creation reference is released here.
	windows.CertFreeCertificateContext(certCtx)

	existing, err := findCertBySHA256(store, fp)
	if err != nil {
		t.Fatalf("findCertBySHA256: %v", err)
	}
	if existing == nil {
		t.Fatal("certificate not found in memory store")
	}
	held := windows.CertDuplicateCertificateContext(existing)
	if held == nil {
		t.Fatal("CertDuplicateCertificateContext returned nil")
	}
	defer windows.CertFreeCertificateContext(held)

	// Ownership of existing passes to the delete; it is not used or freed again.
	if err := deleteCertificateFromStore(existing); err != nil {
		t.Fatalf("deleteCertificateFromStore: %v", err)
	}

	if got := sha256.Sum256(unsafe.Slice(held.EncodedCert, int(held.Length))); got != fp {
		t.Fatalf("held reference changed after delete: %x, want %x", got, fp)
	}
	again, err := findCertBySHA256(store, fp)
	if err != nil {
		t.Fatalf("findCertBySHA256 after delete: %v", err)
	}
	if again != nil {
		windows.CertFreeCertificateContext(again)
		t.Fatal("certificate still present in memory store after delete")
	}
}

// TestRemoveTrustPathsDoNotFreeAfterDelete is a source check of the CryptoAPI
// ownership contract: both removal paths delete through
// deleteCertificateFromStore and never call CertFreeCertificateContext (the
// delete already frees the context, also on failure), and the helper itself
// only deletes.
func TestRemoveTrustPathsDoNotFreeAfterDelete(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "truststore_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]int{
		"RemoveTrust":                {"deleteCertificateFromStore": 1, "CertDeleteCertificateFromStore": 0, "CertFreeCertificateContext": 0},
		"RemoveTrustBySHA256":        {"deleteCertificateFromStore": 1, "CertDeleteCertificateFromStore": 0, "CertFreeCertificateContext": 0},
		"deleteCertificateFromStore": {"CertDeleteCertificateFromStore": 1, "CertFreeCertificateContext": 0},
	}
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || want[fn.Name.Name] == nil || fn.Body == nil {
			continue
		}
		seen[fn.Name.Name] = true
		calls := map[string]int{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					calls[fun.Name]++
				case *ast.SelectorExpr:
					calls[fun.Sel.Name]++
				}
			}
			return true
		})
		for name, n := range want[fn.Name.Name] {
			if calls[name] != n {
				t.Errorf("%s calls %s %d times, want %d", fn.Name.Name, name, calls[name], n)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("function %s not found in truststore_windows.go", name)
		}
	}
}
