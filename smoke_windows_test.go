//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// These tests exercise the smoke preflight and cleanup cores with in-memory
// fakes only: no CNG key, trust store or privilege state is read or changed.

var _ MachineKeyDeleter = smokeKeyStore{}

func noPrivilegeCheck(t *testing.T) func() (bool, error) {
	return func() (bool, error) {
		t.Fatal("caller privilege must not be consulted")
		return false, nil
	}
}

func privilegeIs(v bool, err error) func() (bool, error) {
	return func() (bool, error) { return v, err }
}

// ---- smoke preflight ----

func TestSmokePreflightClosesProbeSigner(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
	signer := newFakeCloseSigner()
	var probed []string
	err := preflightSmokeState(tlsDir, func(name string) (crypto.Signer, error) {
		probed = append(probed, name)
		return signer, nil
	}, noPrivilegeCheck(t))
	if err == nil {
		t.Fatal("an existing smoke CA key without the CA DER must fail closed")
	}
	if len(probed) != 1 || probed[0] != SmokeCAKeyName {
		t.Fatalf("probed %q, want exactly [%q]", probed, SmokeCAKeyName)
	}
	if signer.closeCount != 1 {
		t.Fatalf("probe signer closed %d times, want exactly once", signer.closeCount)
	}
}

func TestSmokePreflightReportsProbeCloseFailure(t *testing.T) {
	closeErr := errors.New("close failed")
	signer := newFakeCloseSigner()
	signer.closeErr = closeErr
	err := preflightSmokeState(filepath.Join(t.TempDir(), tlsSubDir), func(string) (crypto.Signer, error) {
		return signer, nil
	}, noPrivilegeCheck(t))
	if err == nil || !errors.Is(err, closeErr) {
		t.Fatalf("want the inconsistent-state failure joined with the close failure, got %v", err)
	}
}

func TestSmokePreflightNoProbeWhenCADERPresent(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), []byte("der"), 0600); err != nil {
		t.Fatal(err)
	}
	err := preflightSmokeState(tlsDir, func(string) (crypto.Signer, error) {
		t.Fatal("the key must not be probed when the CA DER exists")
		return nil, nil
	}, noPrivilegeCheck(t))
	if err != nil {
		t.Fatalf("want nil when the CA DER exists, got %v", err)
	}
}

func TestSmokePreflightServerDERWithoutCADERFailsClosed(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, serverCertFile), []byte("der"), 0600); err != nil {
		t.Fatal(err)
	}
	err := preflightSmokeState(tlsDir, func(string) (crypto.Signer, error) {
		t.Fatal("the key must not be probed when the server DER exists without the CA DER")
		return nil, nil
	}, noPrivilegeCheck(t))
	if !errors.Is(err, ErrInconsistentMachineState) {
		t.Fatalf("want ErrInconsistentMachineState, got %v", err)
	}
}

func TestSmokePreflightUnexpectedOpenErrorFailsClosed(t *testing.T) {
	openErr := errors.New("provider failure")
	err := preflightSmokeState(filepath.Join(t.TempDir(), tlsSubDir), func(string) (crypto.Signer, error) {
		return nil, openErr
	}, noPrivilegeCheck(t))
	if !errors.Is(err, openErr) {
		t.Fatalf("an unexpected open error must be propagated, got %v", err)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("an unexpected open error must not be reported as not found: %v", err)
	}
}

// TestSmokePreflightAmbiguousAbsence reconciles the old public assumption
// ("ErrKeyNotFound means absent") with v0.2.0 semantics: ErrKeyNotFound means "not found or
// not accessible", so first install proceeds only for a privileged caller.
func TestSmokePreflightAmbiguousAbsence(t *testing.T) {
	notFound := func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }
	tlsDir := func() string { return filepath.Join(t.TempDir(), tlsSubDir) }

	if err := preflightSmokeState(tlsDir(), notFound, privilegeIs(true, nil)); err != nil {
		t.Fatalf("privileged caller with ErrKeyNotFound: want nil, got %v", err)
	}

	err := preflightSmokeState(tlsDir(), notFound, privilegeIs(false, nil))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("non-privileged caller with ErrKeyNotFound: want a fail-closed ErrKeyNotFound, got %v", err)
	}

	privErr := errors.New("token query failed")
	err = preflightSmokeState(tlsDir(), notFound, privilegeIs(false, privErr))
	if !errors.Is(err, privErr) || !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("undetermined privilege with ErrKeyNotFound: want both errors, got %v", err)
	}
}

// ---- smoke cleanup ----

// smokeCleanupFixture creates a smoke root holding a CA DER and returns it
// with a trust store that records the DER passed to RemoveTrust.
func smokeCleanupFixture(t *testing.T, removeErr error) (root string, der []byte, ts *fakeTrustStore, removed *[][]byte) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "smoke")
	tlsDir := filepath.Join(root, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	der = []byte("smoke-ca-der")
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), der, 0600); err != nil {
		t.Fatal(err)
	}
	removed = &[][]byte{}
	ts = &fakeTrustStore{remove: func(d []byte) error {
		*removed = append(*removed, d)
		return removeErr
	}}
	return root, der, ts, removed
}

func countingDeleter(ca, server error, calls *int) *fakeKeyDeleter {
	return &fakeKeyDeleter{
		ca:     func() error { *calls++; return ca },
		server: func() error { *calls++; return server },
	}
}

func rootExists(t *testing.T, root string) bool {
	t.Helper()
	_, err := os.Stat(root)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestCleanupSmokeSuccess(t *testing.T) {
	for _, tc := range []struct {
		name      string
		removeErr error
	}{
		{"anchor removed", nil},
		{"anchor already absent", ErrTrustAnchorNotFound},
	} {
		root, der, ts, removed := smokeCleanupFixture(t, tc.removeErr)
		calls := 0
		if err := cleanupSmoke(root, der, ts, countingDeleter(nil, nil, &calls)); err != nil {
			t.Fatalf("%s: want nil, got %v", tc.name, err)
		}
		if len(*removed) != 1 || string((*removed)[0]) != string(der) || calls != 2 {
			t.Fatalf("%s: RemoveTrust calls %d, key deletions %d; want 1 exact-DER removal and 2 deletions", tc.name, len(*removed), calls)
		}
		if rootExists(t, root) {
			t.Fatalf("%s: smoke root must be removed", tc.name)
		}
	}
}

func TestCleanupSmokeReturnsTrustFailure(t *testing.T) {
	trustErr := errors.New("trust store unavailable")
	root, der, ts, _ := smokeCleanupFixture(t, trustErr)
	calls := 0
	err := cleanupSmoke(root, der, ts, countingDeleter(nil, nil, &calls))
	if !errors.Is(err, trustErr) {
		t.Fatalf("want the trust failure returned, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("both key deletions must still be attempted, got %d", calls)
	}
	if rootExists(t, root) {
		t.Fatal("with both deletions confirmed the smoke root is removed even after a trust failure")
	}
}

func TestCleanupSmokeReturnsKeyFailure(t *testing.T) {
	keyErr := errors.New("key in use")
	root, der, ts, _ := smokeCleanupFixture(t, nil)
	calls := 0
	err := cleanupSmoke(root, der, ts, countingDeleter(keyErr, nil, &calls))
	if !errors.Is(err, keyErr) || errors.Is(err, ErrKeyDeletionUnconfirmed) {
		t.Fatalf("want the key failure returned as is, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("the server key deletion must still be attempted, got %d", calls)
	}
	if !rootExists(t, root) {
		t.Fatal("an unconfirmed key deletion must retain the smoke root (CA DER)")
	}
}

func TestCleanupSmokeAggregatesCombinedFailures(t *testing.T) {
	trustErr := errors.New("trust store unavailable")
	caErr := errors.New("ca key in use")
	serverErr := errors.New("server key in use")
	root, der, ts, _ := smokeCleanupFixture(t, trustErr)
	calls := 0
	err := cleanupSmoke(root, der, ts, countingDeleter(caErr, serverErr, &calls))
	for _, want := range []error{trustErr, caErr, serverErr} {
		if !errors.Is(err, want) {
			t.Fatalf("aggregated error must contain %v, got %v", want, err)
		}
	}
	if !rootExists(t, root) {
		t.Fatal("unconfirmed key deletions must retain the smoke root")
	}
}

// TestCleanupSmokeAmbiguousKeyAbsence reconciles the old public assumption
// ("ErrKeyNotFound on delete is idempotent success") with v0.2.0 semantics: a delete that
// reports not found or not accessible is an unconfirmed deletion.
func TestCleanupSmokeAmbiguousKeyAbsence(t *testing.T) {
	root, der, ts, _ := smokeCleanupFixture(t, ErrTrustAnchorNotFound)
	calls := 0
	err := cleanupSmoke(root, der, ts, countingDeleter(ErrKeyNotFound, ErrKeyNotFound, &calls))
	if !errors.Is(err, ErrKeyDeletionUnconfirmed) || !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want ErrKeyDeletionUnconfirmed (matching ErrKeyNotFound), got %v", err)
	}
	if errors.Is(err, ErrTrustAnchorNotFound) {
		t.Fatalf("an absent trust anchor is idempotent success and must not be reported: %v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(root, tlsSubDir, caCertFile))
	if readErr != nil || string(got) != string(der) {
		t.Fatalf("the CA DER must be retained for recovery: %v", readErr)
	}
}
