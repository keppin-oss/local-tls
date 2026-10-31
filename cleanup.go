package localtls

import (
	"errors"
	"fmt"
	"os"
)

// cleanupLocalTLS removes Local-TLS-owned material in the required order:
//
//	remove exact Local CA trust anchor (removeTrust)
//	→ delete exact Local-TLS CA CNG key
//	→ delete exact Local-TLS server CNG key
//	→ remove Local-TLS-owned persisted state directory (tlsDir)
//
// It is best-effort across independently removable artifacts: a failure on one
// artifact does not stop removal of the others. Every failure that cannot be
// attributed to "already absent" is aggregated into the returned error so that
// no security-sensitive artifact failure is silently swallowed.
//
// A key delete that reports ErrKeyNotFound is not a confirmed deletion: the key
// may be absent or merely not accessible to the caller. It is reported as
// ErrKeyDeletionUnconfirmed (still matching ErrKeyNotFound). Whenever a key
// deletion is not confirmed, for that or any other reason, the state directory
// is retained so the persisted CA DER (the exact trust-anchor identity) stays
// available for diagnosis and a retried cleanup. An absent trust anchor
// (ErrTrustAnchorNotFound) remains idempotent success.
//
// removeTrust may be nil to skip trust-anchor removal (the caller is
// responsible for deciding whether skipping is safe and surfacing its own
// boundary error when it is not). keyDeleter may be nil to skip key deletion.
func cleanupLocalTLS(tlsDir string, keyDeleter MachineKeyDeleter, removeTrust func() error) error {
	var errs []error

	if removeTrust != nil {
		if err := removeTrust(); err != nil && !errors.Is(err, ErrTrustAnchorNotFound) {
			errs = append(errs, fmt.Errorf("remove CA trust anchor: %w", err))
		}
	}

	keysUnconfirmed := false
	if keyDeleter != nil {
		if err := keyDeleter.DeleteCAKey(); err != nil {
			keysUnconfirmed = true
			errs = append(errs, keyCleanupError("delete Local-TLS CA key", err))
		}
		if err := keyDeleter.DeleteServerKey(); err != nil {
			keysUnconfirmed = true
			errs = append(errs, keyCleanupError("delete Local-TLS server key", err))
		}
	}

	if keysUnconfirmed {
		errs = append(errs, fmt.Errorf("TLS state directory %q retained for recovery because a key deletion is not confirmed", tlsDir))
	} else if err := removeStateDir(tlsDir); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// ErrKeyDeletionUnconfirmed indicates that cleanup could not confirm deletion
// of a Local-TLS key because the delete reported ErrKeyNotFound: the key was
// not found or is not accessible to the caller, so nothing was deleted and the
// key may still exist. Errors carrying it also match ErrKeyNotFound.
var ErrKeyDeletionUnconfirmed = errors.New("key deletion unconfirmed")

// keyCleanupError wraps a key delete failure for the aggregated cleanup error.
// A not-found-or-inaccessible result is additionally marked as an unconfirmed
// deletion instead of being swallowed as idempotent success.
func keyCleanupError(op string, err error) error {
	if errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("%s: %w: %w", op, ErrKeyDeletionUnconfirmed, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// removeStateDir removes the Local-TLS-owned state directory. The module owns
// only its TLS material directory (e.g. ...\Agent\tls); it never removes
// parent directories owned by other modules. An absent directory is an
// idempotent success.
func removeStateDir(tlsDir string) error {
	if _, err := os.Stat(tlsDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat TLS state directory %q: %w", tlsDir, err)
	}
	if err := os.RemoveAll(tlsDir); err != nil {
		return fmt.Errorf("remove TLS state directory %q: %w", tlsDir, err)
	}
	return nil
}
