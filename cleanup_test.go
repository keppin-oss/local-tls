package localtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSHA256Fingerprint(t *testing.T) {
	want := ComputeSHA256Fingerprint([]byte("keppin"))
	hexStr := fmt.Sprintf("%x", want[:])

	fp, err := ParseSHA256Fingerprint(hexStr)
	if err != nil {
		t.Fatalf("ParseSHA256Fingerprint: %v", err)
	}
	if fp != want {
		t.Fatalf("round-trip mismatch: %x != %x", fp, want)
	}

	fp, err = ParseSHA256Fingerprint("  " + hexStr + "\n")
	if err != nil {
		t.Fatalf("ParseSHA256Fingerprint(whitespace): %v", err)
	}
	if fp != want {
		t.Fatal("whitespace-trimmed fingerprint mismatch")
	}

	fp, err = ParseSHA256Fingerprint(strings.ToUpper(hexStr))
	if err != nil {
		t.Fatalf("ParseSHA256Fingerprint(uppercase): %v", err)
	}
	if fp != want {
		t.Fatal("uppercase fingerprint mismatch")
	}

	for _, bad := range []string{"", "abc", strings.Repeat("0", 63), strings.Repeat("0", 65)} {
		if _, err := ParseSHA256Fingerprint(bad); err == nil {
			t.Fatalf("ParseSHA256Fingerprint(%q) should fail", bad)
		}
	}
	if _, err := ParseSHA256Fingerprint(strings.Repeat("g", 64)); err == nil {
		t.Fatal("ParseSHA256Fingerprint(non-hex) should fail")
	}
}

// fakeKeyDeleter records the SPKI passed to each delete and returns the
// configured result.
type fakeKeyDeleter struct {
	ca     func(spki []byte) error
	server func(spki []byte) error

	caSPKIs, serverSPKIs [][]byte
}

func (f *fakeKeyDeleter) DeleteCAKey(spki []byte) error {
	f.caSPKIs = append(f.caSPKIs, spki)
	if f.ca != nil {
		return f.ca(spki)
	}
	return nil
}

func (f *fakeKeyDeleter) DeleteServerKey(spki []byte) error {
	f.serverSPKIs = append(f.serverSPKIs, spki)
	if f.server != nil {
		return f.server(spki)
	}
	return nil
}

// cleanupState is a TLS state directory holding a real CA and server
// certificate DER, as the first install writes them.
type cleanupState struct {
	tlsDir          string
	caDER           []byte
	caSPKI, srvSPKI []byte
	caFingerprint   [32]byte
}

// writeCleanupState creates a TLS state directory with a CA and a server
// certificate issued for two in-memory keys.
func writeCleanupState(t *testing.T) cleanupState {
	t.Helper()
	return writeCleanupStateIn(t, filepath.Join(t.TempDir(), "tls"))
}

// writeCleanupStateIn writes the CA and server certificate DERs into tlsDir.
func writeCleanupStateIn(t *testing.T, tlsDir string) cleanupState {
	t.Helper()
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, err := generateCAWithSigner(now, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := generateServerCertWithSigner(now, ca, caKey, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), ca.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, serverCertFile), srv.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	return cleanupState{
		tlsDir:        tlsDir,
		caDER:         ca.Raw,
		caSPKI:        ca.RawSubjectPublicKeyInfo,
		srvSPKI:       srv.RawSubjectPublicKeyInfo,
		caFingerprint: sha256.Sum256(ca.Raw),
	}
}

// request is the production-shaped cleanup request on the state, with a trust
// removal that records the CA DER it was given.
func (st cleanupState) request(keys MachineKeyDeleter, trustErr error, gotCA *[]byte) cleanupRequest {
	return cleanupRequest{
		stateDir: st.tlsDir,
		derDir:   st.tlsDir,
		keys:     keys,
		removeTrust: func(ca certRecord) error {
			if gotCA != nil {
				*gotCA = ca.der
			}
			return trustErr
		},
	}
}

func assertRetained(t *testing.T, st cleanupState) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(st.tlsDir, caCertFile)); err != nil {
		t.Fatalf("CA DER must be retained for recovery: %v", err)
	}
}

func assertRemoved(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state directory still exists: %v", err)
	}
}

// TestCleanupLocalTLSFullSuccess proves the complete cleanup: the trust anchor
// is removed by the CA DER, each key is deleted with the SPKI of its own
// certificate, and the state directory is removed.
func TestCleanupLocalTLSFullSuccess(t *testing.T) {
	st := writeCleanupState(t)
	keys := &fakeKeyDeleter{}
	var gotCA []byte
	if err := cleanupLocalTLS(st.request(keys, nil, &gotCA)); err != nil {
		t.Fatalf("cleanupLocalTLS: %v", err)
	}
	if !bytes.Equal(gotCA, st.caDER) {
		t.Fatal("trust removal did not receive the on-disk CA DER")
	}
	if len(keys.caSPKIs) != 1 || !bytes.Equal(keys.caSPKIs[0], st.caSPKI) {
		t.Fatalf("CA key delete got %x, want the CA certificate SPKI", keys.caSPKIs)
	}
	if len(keys.serverSPKIs) != 1 || !bytes.Equal(keys.serverSPKIs[0], st.srvSPKI) {
		t.Fatalf("server key delete got %x, want the server certificate SPKI", keys.serverSPKIs)
	}
	assertRemoved(t, st.tlsDir)
}

// TestCleanupLocalTLSAbsentTrustIsIdempotent proves an already-absent trust
// anchor is a confirmed removal.
func TestCleanupLocalTLSAbsentTrustIsIdempotent(t *testing.T) {
	st := writeCleanupState(t)
	if err := cleanupLocalTLS(st.request(&fakeKeyDeleter{}, fmt.Errorf("%w", ErrTrustAnchorNotFound), nil)); err != nil {
		t.Fatalf("expected nil for an absent trust anchor, got %v", err)
	}
	assertRemoved(t, st.tlsDir)
}

// TestCleanupLocalTLSKeyNotFoundIsUnconfirmed proves that a key delete
// reporting ErrKeyNotFound (absent OR not accessible) is never reported as a
// successful cleanup and that the state directory with the CA DER is retained.
func TestCleanupLocalTLSKeyNotFoundIsUnconfirmed(t *testing.T) {
	notFound := func([]byte) error { return fmt.Errorf("hr=0x80090016: %w", ErrKeyNotFound) }
	for _, tc := range []struct {
		name       string
		ca, server func([]byte) error
	}{
		{"ca", notFound, nil},
		{"server", nil, notFound},
		{"both", notFound, notFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := writeCleanupState(t)
			err := cleanupLocalTLS(st.request(&fakeKeyDeleter{ca: tc.ca, server: tc.server}, nil, nil))
			if err == nil {
				t.Fatal("cleanup reported success although a key deletion was not confirmed")
			}
			if !errors.Is(err, ErrKeyDeletionUnconfirmed) || !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("error must match ErrKeyDeletionUnconfirmed and ErrKeyNotFound: %v", err)
			}
			if !strings.Contains(err.Error(), "hr=0x80090016") {
				t.Fatalf("native HRESULT context lost: %v", err)
			}
			assertRetained(t, st)
		})
	}
}

// TestCleanupLocalTLSKeyDeleteFailureRetainsState proves that any failed key
// deletion retains the state directory and is not marked as not-found.
func TestCleanupLocalTLSKeyDeleteFailureRetainsState(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"native delete failure", errors.New("NCryptDeleteKey: hr=0x80090010")},
		{"verification failed", fmt.Errorf("%w: SPKI differs", ErrDeleteVerificationFailed)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := writeCleanupState(t)
			err := cleanupLocalTLS(st.request(&fakeKeyDeleter{server: func([]byte) error { return tc.err }}, nil, nil))
			if !errors.Is(err, tc.err) {
				t.Fatalf("error does not contain the delete failure: %v", err)
			}
			if errors.Is(err, ErrKeyDeletionUnconfirmed) || errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("a non-not-found failure must not be converted: %v", err)
			}
			assertRetained(t, st)
		})
	}
}

// TestCleanupLocalTLSTrustFailureRetainsState proves that a failed trust
// anchor removal keeps the state directory, and with it the CA DER needed to
// retry the removal by exact match, even when both keys were deleted.
func TestCleanupLocalTLSTrustFailureRetainsState(t *testing.T) {
	st := writeCleanupState(t)
	trustErr := errors.New("trust store unavailable")
	keys := &fakeKeyDeleter{}
	err := cleanupLocalTLS(st.request(keys, trustErr, nil))
	if !errors.Is(err, trustErr) {
		t.Fatalf("error does not contain the trust failure: %v", err)
	}
	if len(keys.caSPKIs) != 1 || len(keys.serverSPKIs) != 1 {
		t.Fatal("a trust failure must not stop the key deletions")
	}
	assertRetained(t, st)
}

// TestCleanupLocalTLSMissingDERNotCompletable proves that a key whose DER is
// missing, unreadable or corrupt is not deleted (no SPKI is derived), that the
// other key is still deleted, and that the state directory is retained.
func TestCleanupLocalTLSMissingDERNotCompletable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		file   string
		mutate func(path string) error
	}{
		{"server DER missing", serverCertFile, os.Remove},
		{"server DER corrupt", serverCertFile, func(p string) error { return os.WriteFile(p, []byte("not a certificate"), 0600) }},
		{"CA DER missing", caCertFile, os.Remove},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := writeCleanupState(t)
			if err := tc.mutate(filepath.Join(st.tlsDir, tc.file)); err != nil {
				t.Fatal(err)
			}
			keys := &fakeKeyDeleter{}
			err := cleanupLocalTLS(cleanupRequest{stateDir: st.tlsDir, derDir: st.tlsDir, keys: keys})
			if !errors.Is(err, ErrKeyDeletionNotCompletable) {
				t.Fatalf("err = %v, want ErrKeyDeletionNotCompletable", err)
			}
			caDeleted, srvDeleted := len(keys.caSPKIs), len(keys.serverSPKIs)
			if tc.file == serverCertFile && (caDeleted != 1 || srvDeleted != 0) {
				t.Fatalf("deletes CA=%d server=%d, want 1/0", caDeleted, srvDeleted)
			}
			if tc.file == caCertFile && (caDeleted != 0 || srvDeleted != 1) {
				t.Fatalf("deletes CA=%d server=%d, want 0/1", caDeleted, srvDeleted)
			}
			if _, statErr := os.Stat(st.tlsDir); statErr != nil {
				t.Fatalf("state directory must be retained: %v", statErr)
			}
		})
	}
}

// TestCleanupLocalTLSNamedCAConflict proves that a CA DER on disk whose
// fingerprint is not the one the caller names does not identify the CA key:
// the CA key is not deleted, the server key is, and the state is retained.
func TestCleanupLocalTLSNamedCAConflict(t *testing.T) {
	st := writeCleanupState(t)
	other := sha256.Sum256([]byte("another CA"))
	keys := &fakeKeyDeleter{}
	err := cleanupLocalTLS(cleanupRequest{stateDir: st.tlsDir, derDir: st.tlsDir, keys: keys, namedCA: &other})
	if !errors.Is(err, ErrKeyDeletionNotCompletable) || !strings.Contains(err.Error(), "not the CA named by the caller") {
		t.Fatalf("err = %v, want a not-completable CA key deletion for the conflict", err)
	}
	if len(keys.caSPKIs) != 0 || len(keys.serverSPKIs) != 1 {
		t.Fatalf("deletes CA=%d server=%d, want 0/1", len(keys.caSPKIs), len(keys.serverSPKIs))
	}
	assertRetained(t, st)

	// The matching fingerprint is no conflict.
	keys = &fakeKeyDeleter{}
	if err := cleanupLocalTLS(cleanupRequest{stateDir: st.tlsDir, derDir: st.tlsDir, keys: keys, namedCA: &st.caFingerprint}); err != nil {
		t.Fatalf("matching named CA: %v", err)
	}
}

// TestCleanupLocalTLSPartialFailureIsObservable proves that every failure is
// in the aggregated error.
func TestCleanupLocalTLSPartialFailureIsObservable(t *testing.T) {
	st := writeCleanupState(t)
	trustErr := errors.New("trust store unavailable")
	caErr := errors.New("CA key in use")
	keys := &fakeKeyDeleter{
		ca:     func([]byte) error { return caErr },
		server: func([]byte) error { return fmt.Errorf("key absent: %w", ErrKeyNotFound) },
	}
	err := cleanupLocalTLS(st.request(keys, trustErr, nil))
	for _, want := range []error{trustErr, caErr, ErrKeyDeletionUnconfirmed} {
		if !errors.Is(err, want) {
			t.Errorf("joined error %v does not contain %v", err, want)
		}
	}
	assertRetained(t, st)
}

// TestCleanupLocalTLSRepeatedCleanup proves that a cleanup repeated after a
// complete one deletes nothing: without the DERs no key identity is recorded,
// so both deletions are not completable, and the state directory is not
// recreated.
func TestCleanupLocalTLSRepeatedCleanup(t *testing.T) {
	st := writeCleanupState(t)
	if err := cleanupLocalTLS(st.request(&fakeKeyDeleter{}, nil, nil)); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}

	keys := &fakeKeyDeleter{}
	err := cleanupLocalTLS(st.request(keys, fmt.Errorf("%w", ErrTrustAnchorNotFound), nil))
	if !errors.Is(err, ErrKeyDeletionNotCompletable) {
		t.Fatalf("second cleanup: want ErrKeyDeletionNotCompletable, got %v", err)
	}
	if len(keys.caSPKIs)+len(keys.serverSPKIs) != 0 {
		t.Fatal("a key was deleted without a recorded identity")
	}
	assertRemoved(t, st.tlsDir)
}

func TestRemoveStateDir(t *testing.T) {
	root := t.TempDir()
	tlsDir := filepath.Join(root, "tls")

	// Absent: success.
	if err := removeStateDir(tlsDir); err != nil {
		t.Fatalf("removeStateDir(absent): %v", err)
	}

	// Present with a file: removed.
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := removeStateDir(tlsDir); err != nil {
		t.Fatalf("removeStateDir(present): %v", err)
	}
	if _, err := os.Stat(tlsDir); !os.IsNotExist(err) {
		t.Fatalf("state directory still exists: %v", err)
	}
}
