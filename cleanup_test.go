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

func TestCleanupLocalTLSIdempotentAbsentArtifacts(t *testing.T) {
	// Everything already absent: trust not found, both keys not found, and
	// the state directory does not exist. Must return nil.
	tlsDir := filepath.Join(t.TempDir(), "tls")

	removeTrustCalled := false
	keyDeleter := &fakeKeyDeleter{
		ca:     func() error { return fmt.Errorf("key absent: %w", ErrKeyNotFound) },
		server: func() error { return fmt.Errorf("key absent: %w", ErrKeyNotFound) },
	}

	err := cleanupLocalTLS(tlsDir, keyDeleter, func() error {
		removeTrustCalled = true
		return fmt.Errorf("%w", ErrTrustAnchorNotFound)
	})
	if err != nil {
		t.Fatalf("expected nil for fully-absent cleanup, got %v", err)
	}
	if !removeTrustCalled {
		t.Fatal("removeTrust was not called")
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

	// Second cleanup: everything now absent (not-found) — must still succeed.
	keyDeleter := &fakeKeyDeleter{
		ca:     func() error { return fmt.Errorf("%w", ErrKeyNotFound) },
		server: func() error { return fmt.Errorf("%w", ErrKeyNotFound) },
	}
	if err := cleanupLocalTLS(tlsDir, keyDeleter, func() error { return fmt.Errorf("%w", ErrTrustAnchorNotFound) }); err != nil {
		t.Fatalf("second cleanup: %v", err)
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
