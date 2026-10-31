package localtls

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

type fakeKeyDeleter struct {
	ca     func() error
	server func() error
}

func (f *fakeKeyDeleter) DeleteCAKey() error {
	if f.ca != nil {
		return f.ca()
	}
	return nil
}

func (f *fakeKeyDeleter) DeleteServerKey() error {
	if f.server != nil {
		return f.server()
	}
	return nil
}

func TestCleanupLocalTLSFullSuccess(t *testing.T) {
	root := t.TempDir()
	tlsDir := filepath.Join(root, "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	removeTrustCalled := false
	err := cleanupLocalTLS(tlsDir, &fakeKeyDeleter{}, func() error {
		removeTrustCalled = true
		return nil
	})
	if err != nil {
		t.Fatalf("cleanupLocalTLS: %v", err)
	}
	if !removeTrustCalled {
		t.Fatal("removeTrust was not called")
	}
	if _, statErr := os.Stat(tlsDir); !os.IsNotExist(statErr) {
		t.Fatalf("state directory still exists: %v", statErr)
	}
}

func TestCleanupLocalTLSIdempotentAbsentTrustAndState(t *testing.T) {
	// Trust anchor not found and state directory absent, keys deleted: an
	// already-absent trust anchor and directory are idempotent success.
	tlsDir := filepath.Join(t.TempDir(), "tls")

	removeTrustCalled := false
	err := cleanupLocalTLS(tlsDir, &fakeKeyDeleter{}, func() error {
		removeTrustCalled = true
		return fmt.Errorf("%w", ErrTrustAnchorNotFound)
	})
	if err != nil {
		t.Fatalf("expected nil for absent trust anchor and state, got %v", err)
	}
	if !removeTrustCalled {
		t.Fatal("removeTrust was not called")
	}
}

// writeCleanupState creates a TLS state directory holding a CA DER.
func writeCleanupState(t *testing.T) string {
	t.Helper()
	tlsDir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), []byte("ca-der"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return tlsDir
}

// TestCleanupLocalTLSKeyNotFoundIsUnconfirmed proves that a key delete
// reporting ErrKeyNotFound (absent OR not accessible) is never reported as a
// successful cleanup and that the state directory with the CA DER is retained.
func TestCleanupLocalTLSKeyNotFoundIsUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ca     func() error
		server func() error
	}{
		{"ca", func() error { return fmt.Errorf("hr=0x80090016: %w", ErrKeyNotFound) }, nil},
		{"server", nil, func() error { return fmt.Errorf("hr=0x80090016: %w", ErrKeyNotFound) }},
		{"both", func() error { return fmt.Errorf("hr=0x80090016: %w", ErrKeyNotFound) }, func() error { return ErrKeyNotFound }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsDir := writeCleanupState(t)

			err := cleanupLocalTLS(tlsDir, &fakeKeyDeleter{ca: tc.ca, server: tc.server}, func() error { return nil })
			if err == nil {
				t.Fatal("cleanup reported success although a key deletion was not confirmed")
			}
			if !errors.Is(err, ErrKeyDeletionUnconfirmed) {
				t.Fatalf("error does not match ErrKeyDeletionUnconfirmed: %v", err)
			}
			if !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("error must still match ErrKeyNotFound: %v", err)
			}
			if tc.ca != nil && !strings.Contains(err.Error(), "hr=0x80090016") {
				t.Fatalf("native HRESULT context lost: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(tlsDir, caCertFile)); statErr != nil {
				t.Fatalf("CA DER must be retained for recovery: %v", statErr)
			}
		})
	}
}

// TestCleanupLocalTLSKeyDeleteFailureRetainsState proves that any failed key
// deletion retains the state directory and is not marked as not-found.
func TestCleanupLocalTLSKeyDeleteFailureRetainsState(t *testing.T) {
	tlsDir := writeCleanupState(t)
	accessErr := errors.New("NCryptDeleteKey: hr=0x80090010")

	err := cleanupLocalTLS(tlsDir, &fakeKeyDeleter{server: func() error { return accessErr }}, func() error { return nil })
	if !errors.Is(err, accessErr) {
		t.Fatalf("error does not contain the delete failure: %v", err)
	}
	if errors.Is(err, ErrKeyDeletionUnconfirmed) || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("a non-not-found failure must not be converted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(tlsDir, caCertFile)); statErr != nil {
		t.Fatalf("CA DER must be retained for recovery: %v", statErr)
	}
}

func TestCleanupLocalTLSPartialFailureIsObservable(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), "tls")

	trustErr := errors.New("trust store unavailable")
	caErr := errors.New("CA key in use")

	keyDeleter := &fakeKeyDeleter{
		ca:     func() error { return caErr },
		server: func() error { return fmt.Errorf("key absent: %w", ErrKeyNotFound) },
	}

	err := cleanupLocalTLS(tlsDir, keyDeleter, func() error { return trustErr })
	if err == nil {
		t.Fatal("expected observable error for partial failure")
	}
	if !errors.Is(err, trustErr) {
		t.Errorf("joined error does not contain trust error: %v", err)
	}
	if !errors.Is(err, caErr) {
		t.Errorf("joined error does not contain CA key error: %v", err)
	}
}

func TestCleanupLocalTLSRepeatedCleanup(t *testing.T) {
	// First cleanup: full success with a real state dir.
	root := t.TempDir()
	tlsDir := filepath.Join(root, "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := cleanupLocalTLS(tlsDir, &fakeKeyDeleter{}, func() error { return nil }); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}

	// Second cleanup: the keys now report not-found. That does not prove they
	// were deleted, so the repeated cleanup is observable rather than nil.
	keyDeleter := &fakeKeyDeleter{
		ca:     func() error { return fmt.Errorf("%w", ErrKeyNotFound) },
		server: func() error { return fmt.Errorf("%w", ErrKeyNotFound) },
	}
	err := cleanupLocalTLS(tlsDir, keyDeleter, func() error { return fmt.Errorf("%w", ErrTrustAnchorNotFound) })
	if !errors.Is(err, ErrKeyDeletionUnconfirmed) {
		t.Fatalf("second cleanup: want ErrKeyDeletionUnconfirmed, got %v", err)
	}
	if _, statErr := os.Stat(tlsDir); !os.IsNotExist(statErr) {
		t.Fatalf("second cleanup must not recreate the state directory: %v", statErr)
	}
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
