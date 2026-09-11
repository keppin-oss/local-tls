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
// removeTrust may be nil to skip trust-anchor removal (the caller is
// responsible for deciding whether skipping is safe and surfacing its own
// boundary error when it is not). keyDeleter may be nil to skip key deletion.
func cleanupLocalTLS(tlsDir string, keyDeleter MachineKeyDeleter, removeTrust func() error) error {
	var errs []error

	if removeTrust != nil {
		if err := removeTrust(); err != nil {
			errs = appendCleanupError(errs, "remove CA trust anchor", err)
		}
	}

	if keyDeleter != nil {
		if err := keyDeleter.DeleteCAKey(); err != nil {
			errs = appendCleanupError(errs, "delete Local-TLS CA key", err)
		}
		if err := keyDeleter.DeleteServerKey(); err != nil {
			errs = appendCleanupError(errs, "delete Local-TLS server key", err)
		}
	}

	if err := removeStateDir(tlsDir); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// appendCleanupError appends a wrapped error unless it signals that the
// artifact was already absent (idempotent success).
func appendCleanupError(errs []error, op string, err error) []error {
	if err == nil {
		return errs
	}
	if errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrTrustAnchorNotFound) {
		return errs
	}
	return append(errs, fmt.Errorf("%s: %w", op, err))
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
