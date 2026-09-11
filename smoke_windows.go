//go:build windows

package localtls

import (
	"crypto"
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
	if !fileExists(caPath) {
		if _, err := TestOpenKey(SmokeCAKeyName); err == nil {
			return Material{}, fmt.Errorf(
				"inconsistent smoke state: CNG key %q exists but CA certificate is missing in %s — "+
					"automatic CA regeneration is forbidden; run the smoke cleanup first",
				SmokeCAKeyName, filepath.Join(rootDir, "tls"),
			)
		}
	}

	return ProvisionWithKeyStore(rootDir, smokeKeyStore{}, trustStore, time.Now)
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
func CleanupSmoke(rootDir string, caCertDER []byte) error {
	// 1. Remove CA from LocalMachine\Root by exact fingerprint.
	trustStore, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("platform trust store: %w", err)
	}
	if err := trustStore.RemoveTrust(caCertDER); err != nil {
		// Non-fatal: the cert may not be in the store.
		// We log a warning but continue cleanup.
		fmt.Fprintf(os.Stderr, "WARNING: RemoveTrust (smoke CA): %v\n", err)
	}

	// 2. Delete CNG test keys by exact name.
	for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
		if err := TestDeleteKey(name); err != nil {
			// Non-fatal: key may not exist (e.g. never provisioned).
			fmt.Fprintf(os.Stderr, "WARNING: TestDeleteKey %q: %v\n", name, err)
		}
	}

	// 3. Remove the state directory.
	if err := os.RemoveAll(rootDir); err != nil {
		return fmt.Errorf("remove smoke state directory %q: %w", rootDir, err)
	}

	return nil
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
