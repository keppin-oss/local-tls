package localtls

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// cleanupRequest describes one removal of Local-TLS-owned material.
type cleanupRequest struct {
	// stateDir is the directory removed when every artifact is confirmed.
	stateDir string
	// derDir holds ca-cert.der and server-cert.der, the recorded identities of
	// the CA and server keys.
	derDir string
	// keys deletes the keys; nil skips key deletion.
	keys MachineKeyDeleter
	// removeTrust removes the CA trust anchor. It receives the snapshot of the
	// CA DER taken before any change. nil skips trust removal.
	removeTrust func(ca certRecord) error
	// namedCA, when set, is the SHA-256 fingerprint of the CA certificate the
	// caller names. A CA DER on disk with another fingerprint is a conflict and
	// is not used to identify the CA key.
	namedCA *[32]byte
}

// certRecord is the snapshot of one persisted certificate DER. err is set when
// the file is missing, unreadable or does not parse.
type certRecord struct {
	path string
	der  []byte
	cert *x509.Certificate
	err  error
}

// readCertRecord reads and parses one persisted certificate for cleanup.
func readCertRecord(path string) certRecord {
	r := certRecord{path: path}
	der, err := osFS.readFile(path)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return r
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		r.err = fmt.Errorf("parse %s: %w", path, err)
		return r
	}
	r.der, r.cert = der, cert
	return r
}

// cleanupLocalTLS removes Local-TLS-owned material in the required order:
//
//	snapshot the CA and server certificate DERs (before any change)
//	→ remove the exact Local CA trust anchor
//	→ delete the exact Local-TLS CA key, verified against the CA DER's SPKI
//	→ delete the exact Local-TLS server key, verified against the server DER's SPKI
//	→ remove the Local-TLS-owned state directory
//
// The SubjectPublicKeyInfo of each persisted certificate is the recorded
// identity of its key. It is never derived by opening the key name. A missing,
// unreadable or unparseable DER makes the deletion of that key not completable
// (ErrKeyDeletionNotCompletable): it is not attempted, and the other key is
// still processed. When the caller names a CA fingerprint (namedCA) that does
// not match the CA DER on disk, that DER is not used to identify the CA key.
//
// It is best-effort across independently removable artifacts: a failure on one
// artifact does not stop removal of the others. Every failure that cannot be
// attributed to "already absent" is aggregated into the returned error. An
// absent trust anchor (ErrTrustAnchorNotFound) is idempotent success; a key
// delete reporting ErrKeyNotFound is not a confirmed deletion and is reported
// as ErrKeyDeletionUnconfirmed.
//
// The state directory, with the DERs that identify the trust anchor and the
// keys, is removed only when the trust anchor removal and both key deletions
// are confirmed. Otherwise it is kept for diagnosis and a retried cleanup.
func cleanupLocalTLS(req cleanupRequest) error {
	ca := readCertRecord(filepath.Join(req.derDir, caCertFile))
	server := readCertRecord(filepath.Join(req.derDir, serverCertFile))

	var errs []error
	confirmed := true

	if req.removeTrust != nil {
		if err := req.removeTrust(ca); err != nil && !errors.Is(err, ErrTrustAnchorNotFound) {
			confirmed = false
			errs = append(errs, fmt.Errorf("remove CA trust anchor: %w", err))
		}
	}

	if req.keys != nil {
		caIdentity := ca
		if ca.err == nil && req.namedCA != nil && sha256.Sum256(ca.der) != *req.namedCA {
			caIdentity.err = fmt.Errorf("the CA certificate %s (SHA-256 %x) is not the CA named by the caller (SHA-256 %x); it does not identify the CA key to delete",
				ca.path, sha256.Sum256(ca.der), *req.namedCA)
		}
		if err := deleteRecordedKey("CA", caIdentity, req.keys.DeleteCAKey); err != nil {
			confirmed = false
			errs = append(errs, err)
		}
		if err := deleteRecordedKey("server", server, req.keys.DeleteServerKey); err != nil {
			confirmed = false
			errs = append(errs, err)
		}
	}

	if !confirmed {
		errs = append(errs, fmt.Errorf("TLS state directory %q retained for recovery because the cleanup is not confirmed", req.stateDir))
	} else if err := removeStateDir(req.stateDir); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// deleteRecordedKey deletes one key through the SubjectPublicKeyInfo of its
// persisted certificate. Without a usable certificate the deletion is not
// attempted and is reported as ErrKeyDeletionNotCompletable.
func deleteRecordedKey(role string, rec certRecord, del func([]byte) error) error {
	op := fmt.Sprintf("delete Local-TLS %s key", role)
	if rec.err != nil {
		return fmt.Errorf("%s: %w: %w", op, ErrKeyDeletionNotCompletable, rec.err)
	}
	spki := rec.cert.RawSubjectPublicKeyInfo
	if err := del(spki); err != nil {
		return keyCleanupError(fmt.Sprintf("%s (SPKI SHA-256 %x)", op, sha256.Sum256(spki)), err)
	}
	return nil
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
func removeStateDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat TLS state directory %q: %w", dir, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove TLS state directory %q: %w", dir, err)
	}
	return nil
}
