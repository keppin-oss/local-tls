//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---- LTL-003: smoke cleanup must not hide removal failures ----

func TestCleanupSmokeToleratesAbsentArtifacts(t *testing.T) {
	err := cleanupSmoke(
		filepath.Join(t.TempDir(), "missing"),
		func() error { return ErrTrustAnchorNotFound },
		func(string) error { return ErrKeyNotFound },
	)
	if err != nil {
		t.Fatalf("expected nil for fully-absent smoke cleanup, got %v", err)
	}
}

func TestCleanupSmokeReturnsTrustFailure(t *testing.T) {
	trustErr := errors.New("trust store unavailable")
	err := cleanupSmoke(
		filepath.Join(t.TempDir(), "missing"),
		func() error { return trustErr },
		func(string) error { return ErrKeyNotFound },
	)
	if !errors.Is(err, trustErr) {
		t.Fatalf("expected trust failure to be returned, got %v", err)
	}
}

func TestCleanupSmokeReturnsKeyFailure(t *testing.T) {
	keyErr := errors.New("key in use")
	err := cleanupSmoke(
		filepath.Join(t.TempDir(), "missing"),
		func() error { return ErrTrustAnchorNotFound },
		func(string) error { return keyErr },
	)
	if !errors.Is(err, keyErr) {
		t.Fatalf("expected key failure to be returned, got %v", err)
	}
}

func TestCleanupSmokeContinuesAfterFailure(t *testing.T) {
	trustErr := errors.New("trust store unavailable")
	deleteCalls := 0
	err := cleanupSmoke(
		filepath.Join(t.TempDir(), "missing"),
		func() error { return trustErr },
		func(string) error { deleteCalls++; return ErrKeyNotFound },
	)
	if !errors.Is(err, trustErr) {
		t.Fatalf("expected trust failure to be returned, got %v", err)
	}
	if deleteCalls != 2 {
		t.Fatalf("expected both key deletions to be attempted after trust failure, got %d", deleteCalls)
	}
}

func TestCleanupSmokeAggregatesMultipleFailures(t *testing.T) {
	trustErr := errors.New("trust store unavailable")
	keyErr := errors.New("key in use")
	err := cleanupSmoke(
		filepath.Join(t.TempDir(), "missing"),
		func() error { return trustErr },
		func(string) error { return keyErr },
	)
	if !errors.Is(err, trustErr) || !errors.Is(err, keyErr) {
		t.Fatalf("expected both trust and key failures to be observable, got %v", err)
	}
}

// ---- LTL-004: close the smoke preflight signer ----

func TestSmokePreflightClosesProbeSigner(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "tls", caCertFile) // does not exist

	signer := newFakeCloseSigner()
	var probed string
	err := preflightSmokeState(caPath, func(name string) (crypto.Signer, error) {
		probed = name
		return signer, nil
	})
	if err == nil {
		t.Fatal("expected inconsistent smoke state error")
	}
	if probed != SmokeCAKeyName {
		t.Fatalf("probed name = %q, want %q", probed, SmokeCAKeyName)
	}
	if signer.closeCount != 1 {
		t.Fatalf("probe signer closed %d times, want exactly once", signer.closeCount)
	}
}

func TestSmokePreflightNoProbeWhenCertPresent(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	caPath := filepath.Join(tlsDir, caCertFile)
	if err := os.WriteFile(caPath, []byte("der"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	probed := false
	err := preflightSmokeState(caPath, func(name string) (crypto.Signer, error) {
		probed = true
		return nil, errors.New("unreachable")
	})
	if err != nil {
		t.Fatalf("expected no error when CA cert present, got %v", err)
	}
	if probed {
		t.Fatal("probe must not run when CA cert is present")
	}
}

func TestSmokePreflightAbsentKeyNotInconsistent(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "tls", caCertFile) // does not exist
	err := preflightSmokeState(caPath, func(name string) (crypto.Signer, error) {
		return nil, ErrKeyNotFound
	})
	if err != nil {
		t.Fatalf("expected no error for absent key, got %v", err)
	}
}

func TestSmokePreflightUnexpectedOpenErrorFails(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "tls", caCertFile) // does not exist
	sentinel := errors.New("access denied")
	err := preflightSmokeState(caPath, func(name string) (crypto.Signer, error) {
		return nil, sentinel
	})
	if err == nil {
		t.Fatal("expected unexpected open error to be returned")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("returned error does not wrap the sentinel: %v", err)
	}
}
