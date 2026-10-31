//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"fmt"
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

// DeleteCAKey and DeleteServerKey make smokeKeyStore a MachineKeyDeleter for
// exactly the two smoke key names.
func (s smokeKeyStore) DeleteCAKey() error     { return TestDeleteKey(SmokeCAKeyName) }
func (s smokeKeyStore) DeleteServerKey() error { return TestDeleteKey(SmokeServerKeyName) }

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
	if err := preflightSmokeState(filepath.Join(rootDir, tlsSubDir), TestOpenKey, callerIsPrivileged); err != nil {
		return Material{}, err
	}

	return ProvisionWithKeyStore(rootDir, smokeKeyStore{}, trustStore, time.Now)
}

// preflightSmokeState is the smoke counterpart of the production
// provisionPreCheck and applies the same decision table to the smoke CA
// key: a DER whose presence cannot be determined, a server DER without the CA
// DER, a CA key that opens, any open error other than ErrKeyNotFound, and
// ErrKeyNotFound for a caller that is not privileged (or whose privilege
// cannot be determined) all fail closed. ErrKeyNotFound means "not found or
// not accessible", so it lets the first install proceed only for a privileged
// caller, as a conservative gate rather than a proof of absence.
//
// open is an open-only probe (it never creates a key). A signer it returns is
// closed exactly once; a close failure is reported together with the
// pre-check result. preflightSmokeState never creates, deletes or changes a
// key, the trust store or the caller's privilege.
func preflightSmokeState(tlsDir string, open func(string) (crypto.Signer, error), isPrivileged func() (bool, error)) error {
	var closeErr error
	probe := func(name string) error {
		signer, err := open(name)
		if err != nil {
			return err
		}
		closeErr = closeSigner(signer)
		return nil
	}
	err := provisionPreCheck(tlsDir, SmokeCAKeyName, probe, isPrivileged)
	if closeErr != nil {
		err = errors.Join(err, fmt.Errorf("close smoke CA key probe: %w", closeErr))
	}
	if err != nil {
		return fmt.Errorf("smoke pre-check (run the smoke cleanup first if the state is inconsistent): %w", err)
	}
	return nil
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
// It follows the production cleanup contract (cleanupLocalTLS): every step is
// attempted, and every failure is aggregated and returned rather than printed.
// Only an absent trust anchor (ErrTrustAnchorNotFound) is idempotent success.
// A key delete reporting ErrKeyNotFound ("not found or not accessible") is not
// a confirmed deletion: it is returned as ErrKeyDeletionUnconfirmed and the
// state directory is then retained for diagnosis and a retried cleanup.
// CleanupSmoke returns nil only when the trust anchor is removed or absent,
// both key deletions are confirmed, and the state directory is removed.
//
// An error return does not mean that no cleanup took place. When both key
// deletions are confirmed, removal of rootDir is attempted even if
// trust-anchor removal failed; if that removal succeeds, CleanupSmoke still
// returns the trust-anchor error, with rootDir (and the CA DER it held)
// already removed. rootDir is retained only when a key deletion is not
// confirmed, not on every error. Callers that may need to retry trust-anchor
// removal should therefore preserve the exact CA DER, or its SHA-256
// fingerprint, outside rootDir before calling CleanupSmoke. The fingerprint
// can be passed to CleanupSmokeAnchorBySHA256; it is not a substitute for the
// caCertDER argument of CleanupSmoke.
//
// A retried CleanupSmoke is not guaranteed to return nil. ErrKeyNotFound is
// ambiguous, so it keeps producing ErrKeyDeletionUnconfirmed on every retry,
// even when the key may already be absent. Do not treat that result as a
// confirmed deletion, and do not remove the retained state automatically:
// keep it for diagnosis.
func CleanupSmoke(rootDir string, caCertDER []byte) error {
	trustStore, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("platform trust store: %w", err)
	}
	return cleanupSmoke(rootDir, caCertDER, trustStore, smokeKeyStore{})
}

// cleanupSmoke is the testable core of CleanupSmoke: exact trust-anchor
// removal by DER, exact smoke key deletion and state directory removal, with
// the cleanupLocalTLS aggregation and retention rules.
func cleanupSmoke(rootDir string, caCertDER []byte, trustStore TrustStore, keys MachineKeyDeleter) error {
	return cleanupLocalTLS(rootDir, keys, func() error { return trustStore.RemoveTrust(caCertDER) })
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
