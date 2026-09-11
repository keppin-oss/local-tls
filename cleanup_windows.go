//go:build windows

package localtls

import (
	"fmt"
	"os"
	"path/filepath"
)

// CleanupMachine removes exactly the Local-TLS-owned production material:
//  1. the exact Local CA trust anchor in LocalMachine\Root (identified by the
//     on-disk CA certificate DER);
//  2. the exact persisted Local-TLS CA CNG key;
//  3. the exact persisted Local-TLS server CNG key;
//  4. the Local-TLS-owned TLS state directory (...\Agent\tls).
//
// It is suitable for an elevated installer/uninstaller/repair context and is
// idempotent for artifacts that are already absent.
//
// Cleanup is best-effort across independently removable artifacts, but every
// failure that cannot be attributed to "already absent" is returned so that a
// security-sensitive artifact failure is never silently reported as success.
//
// Trust-anchor removal is by exact SHA-256 fingerprint derived from the on-disk
// CA certificate. If the CA certificate DER (and thus the state directory) is
// already gone, CleanupMachine cannot remove the trust anchor by exact match and
// reports that exact boundary; call CleanupMachineBySHA256 with the known
// fingerprint instead.
func CleanupMachine() error {
	tlsDir, err := MachineTLSPath()
	if err != nil {
		return fmt.Errorf("resolve machine TLS path: %w", err)
	}

	keyDeleter, err := PlatformKeyDeleter()
	if err != nil {
		return fmt.Errorf("platform key deleter: %w", err)
	}

	trustStore, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("platform trust store: %w", err)
	}

	caDERPath := filepath.Join(tlsDir, caCertFile)
	removeTrust := func() error {
		der, err := os.ReadFile(caDERPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf(
					"CA certificate DER is missing at %s: cannot remove the trust anchor by exact match; use CleanupMachineBySHA256 with the exact fingerprint",
					caDERPath,
				)
			}
			return fmt.Errorf("read CA certificate: %w", err)
		}
		return trustStore.RemoveTrust(der)
	}

	return cleanupLocalTLS(tlsDir, keyDeleter, removeTrust)
}

// CleanupMachineBySHA256 is CleanupMachine, but it removes the CA trust anchor
// by its exact SHA-256 fingerprint instead of the on-disk DER. Use it when the
// Local-TLS state directory (and thus the CA certificate DER) has already been
// removed and only the fingerprint is known.
func CleanupMachineBySHA256(fp [32]byte) error {
	tlsDir, err := MachineTLSPath()
	if err != nil {
		return fmt.Errorf("resolve machine TLS path: %w", err)
	}

	keyDeleter, err := PlatformKeyDeleter()
	if err != nil {
		return fmt.Errorf("platform key deleter: %w", err)
	}

	trustStore, err := PlatformTrustStore()
	if err != nil {
		return fmt.Errorf("platform trust store: %w", err)
	}

	removeTrust := func() error {
		return trustStore.RemoveTrustBySHA256(fp)
	}

	return cleanupLocalTLS(tlsDir, keyDeleter, removeTrust)
}
