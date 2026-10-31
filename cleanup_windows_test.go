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

	"github.com/keppin-oss/cng/windowscng"
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
// post-cleanup check lifecycle against test-only smoke namespaces (cleanup is
// confirmed by successful deletes, never by a not-found re-open), and repeats it to
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

// smokeElevationDeps are the key operations establishSmokeElevation uses. The
// elevated test uses TestOpenKey, TestCreateKey and TestDeleteKey; offline
// tests substitute fakes so the SKIP/FAIL classification is covered without
// touching a machine key.
type smokeElevationDeps struct {
	name   func() (string, error)
	open   func(string) (crypto.Signer, error)
	create func(string) (crypto.Signer, error)
	del    func(string) error
}

// establishSmokeElevation verifies the elevated CNG prerequisite by creating
// and deleting a disposable, uniquely-named smoke-namespace test key.
func establishSmokeElevation() (unavailable bool, err error) {
	return establishSmokeElevationWith(smokeElevationDeps{
		name:   uniqueSmokeProbeName,
		open:   TestOpenKey,
		create: TestCreateKey,
		del:    TestDeleteKey,
	})
}

// establishSmokeElevationWith is the body of establishSmokeElevation.
//
// It returns two values that distinguish the two failure classes:
//
//   - unavailable == true: the elevation prerequisite (Administrator CNG write
//     access) is explicitly absent: creating the probe key was denied and CNG
//     reported no failed cleanup of a key created by that call. The caller
//     should SKIP.
//   - unavailable == false && err != nil: an operational failure occurred (for
//     example a signer-close or key-deletion failure after the key was
//     created) — the caller must FAIL.
//
// The probe key name is fresh and random, and an open-only preflight must
// report ErrKeyNotFound before the key is created. ErrKeyNotFound means "not
// found or not accessible", so the preflight does not prove absence; the
// random name is what makes a pre-existing key with that name implausible. A
// key that opens is never reused or deleted, and any other preflight error is
// operational.
//
// Cleanup is confirmed only by a successful delete. A delete that reports
// ErrKeyNotFound did not delete anything and is an operational failure
// (ErrKeyDeletionUnconfirmed), never a skip and never a success.
func establishSmokeElevationWith(deps smokeElevationDeps) (unavailable bool, err error) {
	probeName, err := deps.name()
	if err != nil {
		return false, err
	}

	// Open-only preflight on the fresh name.
	if err := probeKeyOwnership(deps.open, probeName); err != nil {
		return false, err
	}

	// Create the probe key. Only a denied create is the missing prerequisite.
	// A create error does not prove that no key was created: when CNG reports
	// that deleting the key created by the failed call also failed, that key
	// may persist under the exact probe name. That is an operational failure
	// and takes precedence over the text-based prerequisite check (the
	// access-denied text may belong to either part). Nothing is deleted here:
	// the error names the exact probe key for inspection.
	signer, err := deps.create(probeName)
	if err != nil {
		if createCleanupFailed(err) {
			return false, fmt.Errorf("create elevation probe key %q failed and the key created by that call may persist (CNG cleanup failed); inspect and remove that exact key: %w", probeName, err)
		}
		if isElevationUnavailable(err) {
			return true, err
		}
		return false, err
	}

	// The probe key was created by this call. Any failure from here on is
	// operational and must fail the test. If the regular delete below is not
	// reached, still attempt it once and surface its result.
	deleteAttempted := false
	defer func() {
		if deleteAttempted {
			return
		}
		if delErr := deps.del(probeName); delErr != nil {
			err = errors.Join(err, keyCleanupError(fmt.Sprintf("cleanup delete elevation probe key %q", probeName), delErr))
			unavailable = false
		}
	}()

	if cerr := closeSigner(signer); cerr != nil {
		return false, fmt.Errorf("close elevation probe key: %w", cerr)
	}

	deleteAttempted = true
	if delErr := deps.del(probeName); delErr != nil {
		return false, keyCleanupError(fmt.Sprintf("delete elevation probe key %q", probeName), delErr)
	}
	return false, nil
}

// createCleanupFailed reports whether a create error says that the key created
// by the failed call could not be deleted (windowscng.ErrCleanupFailed). The
// sentinel is matched in the chain and, because mapCNGError flattens a chain
// that also carries windowscng.ErrKeyNotFound into text, by its exact message.
func createCleanupFailed(err error) bool {
	return errors.Is(err, windowscng.ErrCleanupFailed) || strings.Contains(err.Error(), windowscng.ErrCleanupFailed.Error())
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
// name. It returns nil only for ErrKeyNotFound ("not found or not accessible";
// not a proof of absence, see establishSmokeElevationWith). A key that
// unexpectedly opens is closed and reported as an error (the key is not ours
// and must not be deleted). Any other open error is returned wrapped.
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
// post-cleanup check cycle against disposable test-owned artifacts. It
// registers a fallback machine-artifact cleanup immediately after successful
// provisioning so that a later failure does not silently leave test-owned CNG
// keys or a trust anchor behind; the fallback reports what it could not
// confirm.
func runSmokeLifecycle(t *testing.T) error {
	root := t.TempDir()
	tlsDir := filepath.Join(root, tlsSubDir)

	material, err := ProvisionSmoke(root)
	if err != nil {
		return fmt.Errorf("ProvisionSmoke: %w", err)
	}

	// Fallback cleanup, needed only when cleanupLocalTLS below did not confirm
	// both key deletions. The state directory is owned by t.TempDir() and
	// removed by the test framework; the CNG keys and trust anchor are not.
	cleanupConfirmed := false
	t.Cleanup(func() {
		if cleanupConfirmed {
			return
		}
		trustStore, tsErr := PlatformTrustStore()
		if tsErr != nil {
			t.Errorf("fallback cleanup: PlatformTrustStore: %v", tsErr)
		} else if err := trustStore.RemoveTrust(material.CACertificate.Raw); err != nil && !errors.Is(err, ErrTrustAnchorNotFound) {
			t.Errorf("fallback cleanup: remove smoke trust anchor: %v", err)
		}
		for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
			if err := TestDeleteKey(name); err != nil {
				t.Errorf("fallback cleanup: %v", keyCleanupError(fmt.Sprintf("delete smoke key %q", name), err))
			}
		}
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

	// cleanupLocalTLS returns nil only when both key deletes succeeded; an
	// ErrKeyNotFound delete is ErrKeyDeletionUnconfirmed and fails here.
	if err := cleanupLocalTLS(tlsDir, smokeKeyDeleter{}, func() error {
		return trustStore.RemoveTrust(material.CACertificate.Raw)
	}); err != nil {
		return fmt.Errorf("cleanupLocalTLS: %w", err)
	}
	cleanupConfirmed = true

	found, err := trustStore.IsTrustedSHA256(material.CAFingerprintSHA256)
	if err != nil {
		return fmt.Errorf("IsTrustedSHA256: %w", err)
	}
	if found {
		return fmt.Errorf("trust anchor still present after cleanup")
	}

	return checkSmokeKeysNotOpenable(TestOpenKey, SmokeCAKeyName, SmokeServerKeyName)
}

// checkSmokeKeysNotOpenable is the post-cleanup consistency check. Deletion is
// already confirmed by the successful deletes; this only catches a key that
// still opens or an unexpected open error. ErrKeyNotFound is consistent with
// the confirmed deletion but is not, by itself, proof that the key is absent.
func checkSmokeKeysNotOpenable(open func(string) (crypto.Signer, error), names ...string) error {
	for _, name := range names {
		signer, err := open(name)
		if err == nil {
			_ = closeSigner(signer)
			return fmt.Errorf("smoke key %q still opens after confirmed deletion", name)
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

// ---- elevation probe SKIP/FAIL classification (offline fakes, no machine key) ----

// fakeElevationKeys records the key operations establishSmokeElevationWith
// performs and returns configured results.
type fakeElevationKeys struct {
	nameErr   error
	openErr   error
	openKey   *fakeCloseSigner
	createErr error
	created   *fakeCloseSigner
	delErrs   []error // result of each successive delete; nil once exhausted
	opens     []string
	creates   []string
	deletes   []string
}

func (f *fakeElevationKeys) deps() smokeElevationDeps {
	return smokeElevationDeps{
		name: func() (string, error) {
			if f.nameErr != nil {
				return "", f.nameErr
			}
			return identity.SmokeKeyNamespace + "elevation-probe-offline", nil
		},
		open: func(name string) (crypto.Signer, error) {
			f.opens = append(f.opens, name)
			if f.openKey != nil {
				return f.openKey, nil
			}
			if f.openErr != nil {
				return nil, f.openErr
			}
			return nil, fmt.Errorf("%w: key %q: hr=0x80090016", ErrKeyNotFound, name)
		},
		create: func(name string) (crypto.Signer, error) {
			f.creates = append(f.creates, name)
			if f.createErr != nil {
				return nil, f.createErr
			}
			f.created = newFakeCloseSigner()
			return f.created, nil
		},
		del: func(name string) error {
			f.deletes = append(f.deletes, name)
			if i := len(f.deletes) - 1; i < len(f.delErrs) {
				return f.delErrs[i]
			}
			return nil
		},
	}
}

// TestEstablishSmokeElevationClassification proves the probe contract offline: a
// denied create is the only SKIP, every failure after the probe key was
// created is an operational FAIL, a delete reporting ErrKeyNotFound is an
// unconfirmed deletion (never success, never SKIP), and success requires a
// confirmed delete of exactly the created key.
func TestEstablishSmokeElevationClassification(t *testing.T) {
	notFound := fmt.Errorf("%w: key %q: hr=0x80090016", ErrKeyNotFound, "probe")
	accessDenied := errors.New("NCryptFinalizeKey: hr=0x80090010")
	closeErr := errors.New("handle close failed")
	inUse := errors.New("key in use")

	cases := []struct {
		name            string
		keys            *fakeElevationKeys
		wantUnavailable bool
		wantErr         []error // each must match; empty means success
		wantCreates     int
		wantDeletes     int
	}{
		{"confirmed delete succeeds", &fakeElevationKeys{}, false, nil, 1, 1},
		{"name generation fails", &fakeElevationKeys{nameErr: errors.New("rng")}, false, []error{}, 0, 0},
		{"preflight opens a key", &fakeElevationKeys{openKey: newFakeCloseSigner()}, false, []error{}, 0, 0},
		{"preflight unexpected error", &fakeElevationKeys{openErr: inUse}, false, []error{inUse}, 0, 0},
		{"create denied is the prerequisite", &fakeElevationKeys{createErr: accessDenied}, true, []error{accessDenied}, 1, 0},
		{"create other error", &fakeElevationKeys{createErr: inUse}, false, []error{inUse}, 1, 0},
		{"delete not found is unconfirmed", &fakeElevationKeys{delErrs: []error{notFound}}, false, []error{ErrKeyDeletionUnconfirmed, ErrKeyNotFound}, 1, 1},
		{"delete access denied is operational", &fakeElevationKeys{delErrs: []error{accessDenied}}, false, []error{accessDenied}, 1, 1},
		{"delete other error", &fakeElevationKeys{delErrs: []error{inUse}}, false, []error{inUse}, 1, 1},
		{"close fails, cleanup delete confirmed", &fakeElevationKeys{}, false, []error{closeErr}, 1, 1},
		{"close fails, cleanup delete not found", &fakeElevationKeys{delErrs: []error{notFound}}, false, []error{closeErr, ErrKeyDeletionUnconfirmed, ErrKeyNotFound}, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.keys.deps()
			if strings.HasPrefix(tc.name, "close fails") {
				create := deps.create
				deps.create = func(name string) (crypto.Signer, error) {
					s, err := create(name)
					tc.keys.created.closeErr = closeErr
					return s, err
				}
			}

			unavailable, err := establishSmokeElevationWith(deps)
			if unavailable != tc.wantUnavailable {
				t.Fatalf("unavailable = %v, want %v (err %v)", unavailable, tc.wantUnavailable, err)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatal("err = nil, want a failure")
				}
				for _, want := range tc.wantErr {
					if !errors.Is(err, want) {
						t.Fatalf("err = %v, want it to match %v", err, want)
					}
				}
			}
			if len(tc.keys.creates) != tc.wantCreates || len(tc.keys.deletes) != tc.wantDeletes {
				t.Fatalf("creates=%d deletes=%d, want %d/%d", len(tc.keys.creates), len(tc.keys.deletes), tc.wantCreates, tc.wantDeletes)
			}
			for _, d := range tc.keys.deletes {
				if len(tc.keys.creates) != 1 || d != tc.keys.creates[0] {
					t.Fatalf("deleted %q, which is not the key this call created (%v)", d, tc.keys.creates)
				}
			}
			if tc.keys.created != nil && tc.keys.created.closeErr == nil && tc.keys.created.closeCount == 0 {
				t.Fatal("the created probe signer must be closed")
			}
			if tc.keys.openKey != nil && !tc.keys.openKey.closed {
				t.Fatal("a key opened by the preflight must be closed and left in place")
			}
		})
	}
}

// TestEstablishSmokeElevationCreateCleanupFailed proves that a create error
// reporting a failed CNG cleanup (windowscng.ErrCleanupFailed: the key created
// by the failed call may persist) is an operational FAIL even when
// access-denied text appears in the original failure or only in the cleanup
// part, including after mapCNGError has flattened the chain to text. The
// original causes and the exact probe name are kept, and nothing is deleted.
// An ordinary denied create without a cleanup failure stays the SKIP
// prerequisite.
func TestEstablishSmokeElevationCreateCleanupFailed(t *testing.T) {
	accessDenied := errors.New("NCryptFinalizeKey: hr=0x80090010")
	cleanupDenied := fmt.Errorf("%w: NCryptDeleteKey: hr=0x80090010", windowscng.ErrCleanupFailed)
	validationErr := errors.New("created key failed post-creation validation")
	flattened := mapCNGError(errors.Join(
		fmt.Errorf("%w: reopen created key", windowscng.ErrKeyNotFound),
		fmt.Errorf("%w: access denied", windowscng.ErrCleanupFailed),
	))
	if errors.Is(flattened, windowscng.ErrCleanupFailed) {
		t.Fatal("fixture: mapCNGError was expected to flatten this chain to text")
	}

	cases := []struct {
		name            string
		createErr       error
		wantUnavailable bool
		wantIs          []error
	}{
		{"denied create with failed cleanup", errors.Join(accessDenied, fmt.Errorf("%w: delete failed", windowscng.ErrCleanupFailed)),
			false, []error{accessDenied, windowscng.ErrCleanupFailed}},
		{"denial only in the cleanup part", errors.Join(validationErr, cleanupDenied),
			false, []error{validationErr, windowscng.ErrCleanupFailed}},
		{"failed cleanup flattened by mapCNGError", flattened,
			false, []error{ErrKeyNotFound}},
		{"ordinary denied create", accessDenied,
			true, []error{accessDenied}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := &fakeElevationKeys{createErr: tc.createErr}
			unavailable, err := establishSmokeElevationWith(keys.deps())
			if unavailable != tc.wantUnavailable {
				t.Fatalf("unavailable = %v, want %v (err %v)", unavailable, tc.wantUnavailable, err)
			}
			for _, want := range tc.wantIs {
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want the original cause %v kept", err, want)
				}
			}
			if !tc.wantUnavailable {
				if len(keys.creates) != 1 || !strings.Contains(err.Error(), keys.creates[0]) {
					t.Fatalf("err = %v, want it to name the exact probe key %v", err, keys.creates)
				}
			}
			if len(keys.opens) != 1 || len(keys.creates) != 1 || len(keys.deletes) != 0 {
				t.Fatalf("opens=%d creates=%d deletes=%d, want 1/1/0 (no key deleted on this path)", len(keys.opens), len(keys.creates), len(keys.deletes))
			}
		})
	}
}

// TestCheckSmokeKeysNotOpenable proves the post-cleanup check fails on a key
// that still opens (closing it) or on an unexpected open error, and accepts
// ErrKeyNotFound only as consistent with an already-confirmed deletion.
func TestCheckSmokeKeysNotOpenable(t *testing.T) {
	notFound := func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }
	if err := checkSmokeKeysNotOpenable(notFound, "a", "b"); err != nil {
		t.Fatalf("not found after confirmed deletion: %v", err)
	}

	signer := newFakeCloseSigner()
	err := checkSmokeKeysNotOpenable(func(string) (crypto.Signer, error) { return signer, nil }, "a")
	if err == nil || !signer.closed {
		t.Fatalf("still-opening key: err = %v, closed = %v; want error and closed signer", err, signer.closed)
	}

	inUse := errors.New("key in use")
	if err := checkSmokeKeysNotOpenable(func(string) (crypto.Signer, error) { return nil, inUse }, "a"); !errors.Is(err, inUse) {
		t.Fatalf("unexpected open error: err = %v, want it wrapped", err)
	}
}
