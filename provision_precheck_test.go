package localtls

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const precheckCAKey = "Keppin.Test.PrecheckCA"

// precheckProbe records calls and returns a fixed result for the CA key.
type precheckProbe struct {
	err   error
	calls int
}

func (p *precheckProbe) probe(name string) error {
	p.calls++
	if name != precheckCAKey {
		return fmt.Errorf("unexpected key %q", name)
	}
	return p.err
}

func privileged(v bool, err error) (func() (bool, error), *int) {
	calls := 0
	return func() (bool, error) {
		calls++
		return v, err
	}, &calls
}

func writePrecheckFile(t *testing.T, tlsDir, name string) {
	t.Helper()
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tlsDir, name), []byte("der"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestProvisionPreCheckCADERPresentProceeds(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
	writePrecheckFile(t, tlsDir, caCertFile)
	p := &precheckProbe{err: errors.New("must not be called")}
	isPriv, privCalls := privileged(false, nil)

	if err := provisionPreCheck(tlsDir, precheckCAKey, p.probe, isPriv); err != nil {
		t.Fatalf("pre-check with CA DER present: %v", err)
	}
	if p.calls != 0 || *privCalls != 0 {
		t.Fatalf("reload path must not probe keys or privilege (probe=%d, priv=%d)", p.calls, *privCalls)
	}
}

func TestProvisionPreCheckServerDERWithoutCADERFailsClosed(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
	writePrecheckFile(t, tlsDir, serverCertFile)
	p := &precheckProbe{err: ErrKeyNotFound}
	isPriv, privCalls := privileged(true, nil)

	err := provisionPreCheck(tlsDir, precheckCAKey, p.probe, isPriv)
	if !errors.Is(err, ErrInconsistentMachineState) {
		t.Fatalf("server DER without CA DER: err = %v, want ErrInconsistentMachineState", err)
	}
	if p.calls != 0 || *privCalls != 0 {
		t.Fatalf("partial state must fail before probing keys or privilege (probe=%d, priv=%d)", p.calls, *privCalls)
	}
}

func TestProvisionPreCheckExistingCAKeyFailsClosed(t *testing.T) {
	tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
	p := &precheckProbe{err: nil}
	isPriv, _ := privileged(true, nil)

	err := provisionPreCheck(tlsDir, precheckCAKey, p.probe, isPriv)
	if err == nil {
		t.Fatal("an existing CA key without CA DER must fail closed")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("existing-key failure must not look like not-found: %v", err)
	}
	if !errors.Is(err, ErrInconsistentMachineState) {
		t.Fatalf("existing-key failure must match ErrInconsistentMachineState: %v", err)
	}
	if !strings.Contains(err.Error(), precheckCAKey) || !strings.Contains(err.Error(), tlsDir) {
		t.Fatalf("existing-key failure must keep its diagnostics (key name, directory): %v", err)
	}
}

// TestProvisionPreCheckAmbiguousOpenErrorsFailClosed proves that open errors
// other than ErrKeyNotFound (access denied, failed validation, provider error)
// never count as a first install, for any caller.
func TestProvisionPreCheckAmbiguousOpenErrorsFailClosed(t *testing.T) {
	for _, openErr := range []error{
		errors.New("NCryptOpenKey: hr=0x80090010"),
		errors.New("existing key failed security validation"),
		errors.New("NCryptOpenStorageProvider: hr=0x80090030"),
	} {
		tlsDir := filepath.Join(t.TempDir(), tlsSubDir)
		p := &precheckProbe{err: openErr}
		isPriv, privCalls := privileged(true, nil)

		err := provisionPreCheck(tlsDir, precheckCAKey, p.probe, isPriv)
		if !errors.Is(err, openErr) {
			t.Fatalf("open error %q: want fail-closed error wrapping it, got %v", openErr, err)
		}
		if *privCalls != 0 {
			t.Fatalf("open error %q: privilege must not rescue an ambiguous open error", openErr)
		}
	}
}

// TestProvisionPreCheckNotFoundRequiresPrivilege proves that ErrKeyNotFound
// (absent OR inaccessible) is a first install only for a privileged caller.
func TestProvisionPreCheckNotFoundRequiresPrivilege(t *testing.T) {
	notFound := fmt.Errorf("%w: key %q: hr=0x80090016", ErrKeyNotFound, precheckCAKey)

	t.Run("non-privileged", func(t *testing.T) {
		isPriv, _ := privileged(false, nil)
		err := provisionPreCheck(filepath.Join(t.TempDir(), tlsSubDir), precheckCAKey, (&precheckProbe{err: notFound}).probe, isPriv)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("want fail-closed error matching ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("privilege-unknown", func(t *testing.T) {
		privErr := errors.New("token query failed")
		isPriv, _ := privileged(true, privErr)
		err := provisionPreCheck(filepath.Join(t.TempDir(), tlsSubDir), precheckCAKey, (&precheckProbe{err: notFound}).probe, isPriv)
		if !errors.Is(err, privErr) || !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("want fail-closed error with both causes, got %v", err)
		}
	})

	t.Run("privileged", func(t *testing.T) {
		isPriv, _ := privileged(true, nil)
		if err := provisionPreCheck(filepath.Join(t.TempDir(), tlsSubDir), precheckCAKey, (&precheckProbe{err: notFound}).probe, isPriv); err != nil {
			t.Fatalf("privileged first install must proceed: %v", err)
		}
	})
}

// TestProvisionPreCheckHealthyFirstInstallAndReload proves the conservative
// gate keeps the healthy flow usable: a privileged first install proceeds into
// ProvisionWithKeyStore, and the following provisioning reloads through the
// CA DER without probing keys and preserves the CA identity.
func TestProvisionPreCheckHealthyFirstInstallAndReload(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	isPriv, _ := privileged(true, nil)

	if err := provisionPreCheck(tlsDir, precheckCAKey, (&precheckProbe{err: ErrKeyNotFound}).probe, isPriv); err != nil {
		t.Fatalf("first-install pre-check: %v", err)
	}
	ks := newFakeMachineKeyStore(true, true)
	m1, err := ProvisionWithKeyStore(dataDir, ks, okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}

	p := &precheckProbe{err: errors.New("must not be called")}
	if err := provisionPreCheck(tlsDir, precheckCAKey, p.probe, isPriv); err != nil || p.calls != 0 {
		t.Fatalf("reload pre-check: err=%v probe calls=%d", err, p.calls)
	}
	m2, err := ProvisionWithKeyStore(dataDir, ks, okTrustStore(), fixedNow(now))
	if err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if m1.CAFingerprintSHA256 != m2.CAFingerprintSHA256 {
		t.Fatal("healthy re-provisioning changed the CA identity")
	}
}

// TestProvisionPreCheckBlocksCAReissueForExistingKey pairs the pre-check with
// the documented ProvisionWithKeyStore behavior: once the CA DER is lost while
// the CA key still opens, the pre-check refuses before a new CA certificate
// could be issued.
func TestProvisionPreCheckBlocksCAReissueForExistingKey(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	if _, err := ProvisionWithKeyStore(dataDir, newFakeMachineKeyStore(true, true), okTrustStore(), fixedNow(now)); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	if err := os.Remove(filepath.Join(tlsDir, caCertFile)); err != nil {
		t.Fatalf("remove CA DER: %v", err)
	}
	if err := os.Remove(filepath.Join(tlsDir, serverCertFile)); err != nil {
		t.Fatalf("remove server DER: %v", err)
	}

	isPriv, _ := privileged(true, nil)
	if err := provisionPreCheck(tlsDir, precheckCAKey, (&precheckProbe{err: nil}).probe, isPriv); err == nil {
		t.Fatal("pre-check must refuse CA reissue while the CA key exists")
	}
}
