//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keppin-oss/local-tls/internal/identity"
)

const smokeKeyPrefix = identity.SmokeKeyNamespace

// smokeKeyStore implements MachineKeyStore but enforces the
// Keppin.Test.Smoke. key-name prefix on all operations.
// It delegates to TestCreateKey (which already enforces Keppin.Test.).
type smokeKeyStore struct{}

func (s smokeKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	return TestCreateKey(SmokeCAKeyName)
}

func (s smokeKeyStore) LoadOrCreateServerKey() (crypto.Signer, error) {
	return TestCreateKey(SmokeServerKeyName)
}

// Smoke key names — explicitly in the Keppin.Test.* namespace.
const (
	SmokeCAKeyName     = identity.SmokeCAKeyName
	SmokeServerKeyName = identity.SmokeServerKeyName
)

// validateSmokeKeyName returns an error if the key name is not in the smoke
// test namespace.
func validateSmokeKeyName(name string) error {
	if !strings.HasPrefix(name, smokeKeyPrefix) {
		return fmt.Errorf("smoke key name must start with %q, got %q", smokeKeyPrefix, name)
	}
	return nil
}

// ProvisionSmoke provisions smoke-test TLS material under the given root
// directory using test-only CNG key names. The root directory should be a
// temporary or clearly scoped test directory, NOT the production machine
// state root.
//
// Requires Administrator elevation (creates machine-scoped CNG keys and
// installs the test CA in LocalMachine\Root).
//
// Repeated provisioning with the same root is idempotent: the same CA
// identity is preserved and the CA certificate is not re-installed if
// already present.
func ProvisionSmoke(rootDir string) (Material, error) {
	if err := validateSmokeKeyName(SmokeCAKeyName); err != nil {
		return Material{}, err
	}
	if err := validateSmokeKeyName(SmokeServerKeyName); err != nil {
		return Material{}, err
	}

	trustStore, err := PlatformTrustStore()
	if err != nil {
		return Material{}, fmt.Errorf("platform trust store: %w", err)
	}

	// Pre-provision safety check: same as production — detect
	// inconsistent state (CNG key exists, cert missing) and fail
	// closed rather than silently regenerating the CA.
	caPath := filepath.Join(rootDir, "tls", caCertFile)
	if err := preflightSmokeState(caPath, TestOpenKey); err != nil {
		return Material{}, err
	}

	return ProvisionWithKeyStore(rootDir, smokeKeyStore{}, trustStore, time.Now)
}

// preflightSmokeState detects the inconsistent smoke state where the CA key
// exists but the CA certificate is missing, failing closed rather than silently
// regenerating the CA. It uses an open-only probe (never creates a key). The
// probe outcome is classified exactly:
//
//   - ErrKeyNotFound: the key is absent; return nil so provisioning may continue.
//   - successful open: the key exists; the returned signer is closed exactly once
//     and the inconsistent-state error is returned.
//   - any other open error (permission, provider, corrupted state, etc.): the
//     unexpected error is preserved and returned; provisioning does NOT continue.
func preflightSmokeState(caPath string, open func(string) (crypto.Signer, error)) error {
	if fileExists(caPath) {
		return nil
	}
	signer, err := open(SmokeCAKeyName)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			// The key is absent: allow provisioning to continue.
			return nil
		}
		// An unexpected open failure must not be converted into key absence.
		return fmt.Errorf("open smoke CA key %q during preflight: %w", SmokeCAKeyName, err)
	}
	inconsistent := fmt.Errorf(
		"inconsistent smoke state: CNG key %q exists but CA certificate is missing in %s — "+
			"automatic CA regeneration is forbidden; run the smoke cleanup first",
		SmokeCAKeyName, filepath.Dir(caPath),
	)
	if cerr := closeSigner(signer); cerr != nil {
		return fmt.Errorf("%w (close probe signer: %v)", inconsistent, cerr)
	}
	return inconsistent
}

// CleanupSmoke removes exactly the smoke-test TLS material.
//
// Performs three exact operations through native CNG APIs:
//  1. Deletes the CA certificate from LocalMachine\Root by exact SHA-256
//     fingerprint (using RemoveTrust).
//  2. Deletes the CNG test keys by exact name (using TestDeleteKey).
//  3. Removes the state directory.
//
// No wildcard/CN-based mutation. No certutil. No external tools.
//
// Cleanup is best-effort across independently removable artifacts: a failure on
// one artifact does not stop removal of the others. Only exact "already absent"
// conditions (ErrTrustAnchorNotFound / ErrKeyNotFound) are suppressed; every
// other trust, key, or filesystem failure is aggregated and returned so smoke
// cleanup never reports success while a machine artifact may still remain.
func CleanupSmoke(rootDir string, caCertDER []byte) error {
	// 1. Remove CA from LocalMachine\Root by exact fingerprint.
	trustStore, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("platform trust store: %w", err)
	}
	removeTrust := func() error {
		return trustStore.RemoveTrust(caCertDER)
	}

	return cleanupSmoke(rootDir, removeTrust, TestDeleteKey)
}

// cleanupSmoke is the testable core of CleanupSmoke. It removes the trust
// anchor, deletes both smoke keys, and removes the state directory, aggregating
// all unexpected failures. Only the exact already-absent sentinels are treated
// as idempotent success.
func cleanupSmoke(rootDir string, removeTrust func() error, deleteKey func(string) error) error {
	var errs []error

	if err := removeTrust(); err != nil {
		if !errors.Is(err, ErrTrustAnchorNotFound) {
			errs = append(errs, fmt.Errorf("remove smoke CA trust anchor: %w", err))
		}
	}

	for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
		if err := deleteKey(name); err != nil {
			if !errors.Is(err, ErrKeyNotFound) {
				errs = append(errs, fmt.Errorf("delete smoke key %q: %w", name, err))
			}
		}
	}

	if err := os.RemoveAll(rootDir); err != nil {
		errs = append(errs, fmt.Errorf("remove smoke state directory %q: %w", rootDir, err))
	}

	return errors.Join(errs...)
}

// VerifySmokeTrust performs a read-only trust verification of the smoke CA
// certificate. Safe for non-elevated use; never mutates Root.
func VerifySmokeTrust(caCertDER []byte) (TrustState, error) {
	trustStore, err := PlatformTrustStore()
	if err != nil {
		return TrustError, fmt.Errorf("platform trust store: %w", err)
	}
	return trustStore.VerifyTrust(caCertDER)
}

// CleanupSmokeAnchorBySHA256 removes exactly one certificate from
// LocalMachine\Root by its SHA-256 fingerprint. Unlike CleanupSmoke,
// this does not require the DER file — it works directly from the
// fingerprint. Use for cleaning up stale anchors after state directory
// deletion or when the original DER is unavailable.
//
// Requires Administrator elevation.
func CleanupSmokeAnchorBySHA256(hexFP string) error {
	fp, err := ParseSHA256Fingerprint(hexFP)
	if err != nil {
		return err
	}

	store, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("platform trust store: %w", err)
	}
	return store.RemoveTrustBySHA256(fp)
}
