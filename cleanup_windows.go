//go:build windows

package localtls

import (
	"fmt"
)

// CleanupMachine removes exactly the Local-TLS-owned production material:
//  1. the exact Local CA trust anchor in LocalMachine\Root (identified by the
//     on-disk CA certificate DER);
//  2. the exact persisted Local-TLS CA CNG key, verified against the
//     SubjectPublicKeyInfo of the on-disk CA certificate;
//  3. the exact persisted Local-TLS server CNG key, verified against the
//     SubjectPublicKeyInfo of the on-disk server certificate;
//  4. the Local-TLS-owned TLS state directory (...\Agent\tls).
//
// It must run as LocalSystem or as an elevated Administrator. Both DERs are
// read once, before anything changes. An already-absent trust anchor or state
// directory is idempotent success.
//
// Cleanup is best-effort across independently removable artifacts, but every
// failure that cannot be attributed to "already absent" is returned so that a
// security-sensitive artifact failure is never silently reported as success.
// A key reported as not found or not accessible is not proof of deletion
// (ErrKeyDeletionUnconfirmed); a key whose DER is missing or unreadable is not
// deleted at all (ErrKeyDeletionNotCompletable); a key that does not hold its
// role policy or the recorded public key is not deleted
// (ErrDeleteVerificationFailed). The TLS state directory, with the DERs, is
// removed only when the trust anchor removal and both key deletions are
// confirmed, so CleanupMachine returns nil only then.
//
// Trust-anchor removal is by exact SHA-256 fingerprint derived from the on-disk
// CA certificate. If the CA certificate DER is already gone, CleanupMachine
// cannot remove the trust anchor by exact match and reports that boundary; call
// CleanupMachineBySHA256 with the known fingerprint instead.
//
// A retried cleanup after a partial one can report a key that this module
// already deleted as ErrKeyDeletionUnconfirmed: without a journal, Local-TLS
// cannot tell that key from one it cannot access. Do not treat such a result as
// success, and do not remove the retained state directory automatically.
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

	return cleanupLocalTLS(cleanupRequest{
		stateDir: tlsDir,
		derDir:   tlsDir,
		keys:     keyDeleter,
		removeTrust: func(ca certRecord) error {
			if ca.err != nil {
				return fmt.Errorf("cannot remove the trust anchor by exact match: %w; use CleanupMachineBySHA256 with the exact fingerprint", ca.err)
			}
			return trustStore.RemoveTrust(ca.der)
		},
	})
}

// CleanupMachineBySHA256 is CleanupMachine, but it removes the CA trust anchor
// by its exact SHA-256 fingerprint fp instead of the on-disk DER. Use it when
// the CA certificate DER is gone and only the fingerprint is known.
//
// The fingerprint identifies a certificate, not a key: it never authorizes the
// deletion of a CNG key. Each key is still deleted only through the
// SubjectPublicKeyInfo of its on-disk certificate; when that DER is missing the
// key is not deleted (ErrKeyDeletionNotCompletable) and the state directory is
// kept. A CA DER on disk whose fingerprint is not fp is reported as a conflict
// and is not used to delete the CA key.
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

	return cleanupLocalTLS(cleanupRequest{
		stateDir:    tlsDir,
		derDir:      tlsDir,
		keys:        keyDeleter,
		removeTrust: func(certRecord) error { return trustStore.RemoveTrustBySHA256(fp) },
		namedCA:     &fp,
	})
}
