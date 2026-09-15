//go:build windows

package localtls

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keppin-oss/local-tls/internal/identity"
)

// TestProductionKeyNamesExact proves the cleanup operates on the exact
// Local-TLS production key names and never on the test/smoke namespace or on
// Machine Identity / Enterprise identities.
func TestProductionKeyNamesExact(t *testing.T) {
	if caKeyName != identity.ProdCAKeyName {
		t.Fatalf("caKeyName = %q, want %q", caKeyName, identity.ProdCAKeyName)
	}
	if serverKeyName != identity.ProdServerKeyName {
		t.Fatalf("serverKeyName = %q, want %q", serverKeyName, identity.ProdServerKeyName)
	}

	for _, name := range []string{caKeyName, serverKeyName} {
		if strings.HasPrefix(name, identity.TestKeyNamespace) {
			t.Errorf("production key %q must not live in the test namespace %q", name, identity.TestKeyNamespace)
		}
		if strings.HasPrefix(name, identity.SmokeKeyNamespace) {
			t.Errorf("production key %q must not live in the smoke namespace %q", name, identity.SmokeKeyNamespace)
		}
	}
}

func TestPlatformKeyDeleterReturnsDeleter(t *testing.T) {
	d, err := PlatformKeyDeleter()
	if err != nil {
		t.Fatalf("PlatformKeyDeleter: %v", err)
	}
	if d == nil {
		t.Fatal("PlatformKeyDeleter returned nil")
	}
	if _, ok := d.(MachineKeyDeleter); !ok {
		t.Fatal("returned value does not implement MachineKeyDeleter")
	}
}

// smokeKeyDeleter reuses the exact production key-deletion path
// (deleteProductionKey) against the smoke test key names so the elevated
// lifecycle smoke never touches production keys.
type smokeKeyDeleter struct{}

func (smokeKeyDeleter) DeleteCAKey() error     { return deleteProductionKey(SmokeCAKeyName) }
func (smokeKeyDeleter) DeleteServerKey() error { return deleteProductionKey(SmokeServerKeyName) }

// TestCleanupLifecycleElevated proves the full provision → verify → cleanup →
// verify-absent lifecycle against test-only smoke namespaces, and repeats it to
// prove repeatability. It requires Administrator elevation and is skipped
// (reported NOT EXECUTED) only when the elevation prerequisite is absent.
//
// Once the prerequisite is established, every operational failure (provision,
// verification, cleanup, or post-cleanup validation) fails the test rather than
// being converted into a skip.
func TestCleanupLifecycleElevated(t *testing.T) {
	unavailable, err := establishSmokeElevation()
	if unavailable {
		t.Skipf("elevated lifecycle smoke requires Administrator: %v — NOT EXECUTED", err)
	}
	if err != nil {
		t.Fatalf("elevation probe failed: %v", err)
	}

	if err := runSmokeLifecycle(t); err != nil {
		t.Fatalf("first lifecycle run failed: %v", err)
	}
	if err := runSmokeLifecycle(t); err != nil {
		t.Fatalf("second lifecycle run failed: %v", err)
	}
}

// establishSmokeElevation verifies the elevated CNG prerequisite by creating
// and deleting a disposable, uniquely-named smoke-namespace test key.
//
// It returns two values that distinguish the two failure classes:
//
//   - unavailable == true: the elevation prerequisite (Administrator CNG write
//     access) is explicitly absent — the caller should SKIP.
//   - unavailable == false && err != nil: an operational failure occurred (for
//     example a signer-close or key-deletion failure after ownership was
//     established) — the caller must FAIL.
//
// Ownership of the probe key is established by construction: a fresh unique name
// is generated, an open-only preflight must report the key as absent
// (ErrKeyNotFound), and only then is the key created. A pre-existing key is
// never reused or deleted, and any unexpected preflight/open error is returned
// as an operational error rather than converted into absence.
func establishSmokeElevation() (unavailable bool, err error) {
	probeName, err := uniqueSmokeProbeName()
	if err != nil {
		return false, err
	}

	// Open-only preflight: the unique name must be absent before we create it.
	if err := probeKeyOwnership(TestOpenKey, probeName); err != nil {
		return false, err
	}

	// Create the previously-absent unique key. Ownership is established only
	// after this succeeds (the key was confirmed absent a moment ago).
	signer, err := TestCreateKey(probeName)
	if err != nil {
		if isElevationUnavailable(err) {
			return true, err
		}
		return false, err
	}

	// Ownership is established. Any failure from here on is operational and must
	// fail the test. Cleanup-attempt the owned probe key even if a later step
	// fails, and surface a failed cleanup rather than discarding it.
	cleanupDone := false
	defer func() {
		if !cleanupDone {
			if delErr := TestDeleteKey(probeName); delErr != nil && !errors.Is(delErr, ErrKeyNotFound) {
				if err != nil {
					err = fmt.Errorf("%w; cleanup delete elevation probe key: %v", err, delErr)
				} else {
					err = fmt.Errorf("cleanup delete elevation probe key: %v", delErr)
				}
				unavailable = false
			}
		}
	}()

	if cerr := closeSigner(signer); cerr != nil {
		return false, fmt.Errorf("close elevation probe key: %w", cerr)
	}

	if delErr := TestDeleteKey(probeName); delErr != nil && !errors.Is(delErr, ErrKeyNotFound) {
		return false, fmt.Errorf("delete elevation probe key: %w", delErr)
	}
	cleanupDone = true
	return false, nil
}

// isElevationUnavailable reports whether err indicates the process lacks the
// Administrator elevation required to create a machine-scoped CNG key. It
// recognizes the CNG access-denied HRESULTs and messages the shared windowscng
// layer surfaces when a non-elevated caller attempts to create a machine key.
func isElevationUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, ind := range []string{
		"access is denied",
		"access denied",
		"0x80090010", // NTE_PERM
		"0x801f0005", // STATUS_ACCESS_DENIED
	} {
		if strings.Contains(msg, ind) {
			return true
		}
	}
	return false
}

// uniqueSmokeProbeName returns a fresh, unique test-only key name under the
// smoke namespace. It never returns a fixed or reusable fixture name.
func uniqueSmokeProbeName() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate elevation probe suffix: %w", err)
	}
	return identity.SmokeKeyNamespace + "elevation-probe-" + hex.EncodeToString(buf[:]), nil
}

// probeKeyOwnership classifies the open-only preflight for a unique probe key
// name. It returns nil only when the key is absent (ErrKeyNotFound). A key that
// unexpectedly already exists is closed and reported as an error (ownership is
// not established and the key must not be deleted). Any other open error is
// returned unchanged (wrapped).
func probeKeyOwnership(open func(string) (crypto.Signer, error), name string) error {
	signer, err := open(name)
	if err == nil {
		_ = closeSigner(signer)
		return fmt.Errorf("elevation probe key %q unexpectedly already exists", name)
	}
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	}
	return fmt.Errorf("open elevation probe key %q: %w", name, err)
}

// runSmokeLifecycle executes one full provision → verify → cleanup →
// verify-absent cycle against disposable test-owned artifacts. It registers
// machine-artifact cleanup immediately after successful provisioning so that a
// later failure cannot leave test-owned CNG keys or a trust anchor behind.
func runSmokeLifecycle(t *testing.T) error {
	root := t.TempDir()
	tlsDir := filepath.Join(root, tlsSubDir)

	material, err := ProvisionSmoke(root)
	if err != nil {
		return fmt.Errorf("ProvisionSmoke: %w", err)
	}

	// Register machine-artifact cleanup immediately after successful
	// provisioning. The state directory is owned by t.TempDir() and removed by
	// the test framework; the CNG keys and trust anchor are not.
	t.Cleanup(func() {
		trustStore, tsErr := PlatformTrustStore()
		if tsErr == nil {
			_ = trustStore.RemoveTrust(material.CACertificate.Raw)
		}
		_ = TestDeleteKey(SmokeCAKeyName)
		_ = TestDeleteKey(SmokeServerKeyName)
		_ = os.RemoveAll(root)
	})

	trustStore, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("PlatformTrustStore: %w", err)
	}

	state, err := VerifySmokeTrust(material.CACertificate.Raw)
	if err != nil {
		return fmt.Errorf("VerifySmokeTrust: %w", err)
	}
	if state != TrustHealthy {
		return fmt.Errorf("expected TrustHealthy, got %s", state)
	}

	if err := cleanupLocalTLS(tlsDir, smokeKeyDeleter{}, func() error {
		return trustStore.RemoveTrust(material.CACertificate.Raw)
	}); err != nil {
		return fmt.Errorf("cleanupLocalTLS: %w", err)
	}

	found, err := trustStore.IsTrustedSHA256(material.CAFingerprintSHA256)
	if err != nil {
		return fmt.Errorf("IsTrustedSHA256: %w", err)
	}
	if found {
		return fmt.Errorf("trust anchor still present after cleanup")
	}

	for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
		_, err := TestOpenKey(name)
		if err == nil {
			return fmt.Errorf("smoke key %q still present after cleanup", name)
		}
		if !errors.Is(err, ErrKeyNotFound) {
			return fmt.Errorf("unexpected error opening smoke key %q after cleanup: %w", name, err)
		}
	}
	return nil
}

// ---- elevation probe ownership decision (no machine mutation) ----

func TestProbeKeyOwnershipAbsent(t *testing.T) {
	err := probeKeyOwnership(func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }, "probe")
	if err != nil {
		t.Fatalf("absent key: expected nil, got %v", err)
	}
}

func TestProbeKeyOwnershipUnexpectedlyPresent(t *testing.T) {
	signer := newFakeCloseSigner()
	err := probeKeyOwnership(func(string) (crypto.Signer, error) { return signer, nil }, "probe")
	if err == nil {
		t.Fatal("expected error for unexpectedly present key")
	}
	if !signer.closed {
		t.Fatal("present key signer must be closed")
	}
}

func TestProbeKeyOwnershipUnexpectedOpenError(t *testing.T) {
	sentinel := errors.New("access denied")
	err := probeKeyOwnership(func(string) (crypto.Signer, error) { return nil, sentinel }, "probe")
	if err == nil {
		t.Fatal("expected unexpected open error to be returned")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("returned error does not wrap the sentinel: %v", err)
	}
}

func TestUniqueSmokeProbeName(t *testing.T) {
	a, err := uniqueSmokeProbeName()
	if err != nil {
		t.Fatalf("uniqueSmokeProbeName: %v", err)
	}
	if !strings.HasPrefix(a, identity.SmokeKeyNamespace) {
		t.Fatalf("probe name %q must start with %q", a, identity.SmokeKeyNamespace)
	}
	b, err := uniqueSmokeProbeName()
	if err != nil {
		t.Fatalf("uniqueSmokeProbeName: %v", err)
	}
	if a == b {
		t.Fatal("two unique probe names must differ")
	}
}

// TestIsElevationUnavailable proves the prerequisite-vs-operational classifier
// recognizes only explicit access-denied conditions, so operational failures
// (such as a key-deletion or signer-close error) are never converted into a
// skip. Non-mutating.
func TestIsElevationUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"nte_perm", errors.New("NCryptFinalizeKey: hr=0x80090010"), true},
		{"status_access_denied", errors.New("access denied 0x801f0005"), true},
		{"access_is_denied", errors.New("Access is denied"), true},
		{"provider_missing", errors.New("NCryptOpenStorageProvider: hr=0x80090011"), false},
		{"key_not_found", ErrKeyNotFound, false},
		{"close_failure", errors.New("close elevation probe key: handle closed"), false},
		{"delete_failure", errors.New("delete elevation probe key: key in use"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isElevationUnavailable(tc.err); got != tc.want {
				t.Fatalf("isElevationUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
