package localtls

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// keyPolicyMigration holds the dependencies of migrateKeyPolicies, the
// platform-independent body of MigrateMachineKeyPolicies. Production wiring is
// in composition_windows.go; unit tests substitute fakes.
type keyPolicyMigration struct {
	tlsDir string
	fs     fileSystem
	// isPrivileged reports whether the caller is LocalSystem or an elevated
	// Administrators member.
	isPrivileged func() (bool, error)
	// openServerKey opens the server key open-only under the service-signer
	// policy; it never writes.
	openServerKey func() (crypto.Signer, error)
	// tightenCAKey brings the existing CA key to the privileged-only policy in
	// place (idempotent, tighten-only, read-back, never creates).
	tightenCAKey func() error
	// openCAKey opens the CA key open-only under the privileged-only policy.
	openCAKey func() (crypto.Signer, error)
}

// migrateKeyPolicies is the body of MigrateMachineKeyPolicies. Its order is:
//
//  1. require a privileged caller (fail closed when that cannot be determined);
//  2. require both certificate DERs to be present and parseable: a partial or
//     unknown state is never migrated;
//  3. read-only: the server key must open under the service-signer policy and
//     match the persisted server certificate;
//  4. tighten the CA key DACL to privileged-only (no-op when already so);
//  5. the CA key must then open under the privileged-only policy and match the
//     persisted CA certificate;
//  6. the CA certificate DER must be byte-for-byte unchanged.
//
// It never creates, rotates, regenerates or deletes a key, never writes a
// certificate and never reads or modifies the trust store. ErrKeyNotFound is
// reported as a failure, never as absence. A failure after step 4 can leave the
// CA key tightened; that is never widened back.
func migrateKeyPolicies(m keyPolicyMigration) error {
	privileged, err := m.isPrivileged()
	if err != nil {
		return fmt.Errorf("%w: privilege check failed: %v", ErrPrivilegeRequired, err)
	}
	if !privileged {
		return ErrPrivilegeRequired
	}

	caDER, caCert, err := m.readMigrationCert(caCertFile, "CA")
	if err != nil {
		return err
	}
	_, serverCert, err := m.readMigrationCert(serverCertFile, "server")
	if err != nil {
		return err
	}

	if err := verifyKeyForCert(m.openServerKey, serverCert, "server"); err != nil {
		return err
	}

	if err := m.tightenCAKey(); err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return fmt.Errorf("tighten CA key policy: the CA key was not found or is not accessible; this does not prove that it is absent and nothing was created: %w", err)
		}
		return fmt.Errorf("tighten CA key policy: %w", err)
	}

	if err := verifyKeyForCert(m.openCAKey, caCert, "CA"); err != nil {
		return err
	}

	after, err := m.fs.readFile(m.path(caCertFile))
	if err != nil {
		return fmt.Errorf("re-read CA certificate after migration: %w", err)
	}
	if !bytes.Equal(after, caDER) {
		return fmt.Errorf("%w: the CA certificate changed during the key policy migration (sha256 %x, now %x); another writer violated the single-writer contract",
			ErrInconsistentMachineState, sha256.Sum256(caDER), sha256.Sum256(after))
	}
	return nil
}

func (m keyPolicyMigration) path(name string) string {
	return filepath.Join(m.tlsDir, name)
}

// readMigrationCert reads and parses one persisted certificate. A missing file
// is inconsistent state for a migration, never a reason to provision.
func (m keyPolicyMigration) readMigrationCert(name, what string) ([]byte, *x509.Certificate, error) {
	der, err := m.fs.readFile(m.path(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s certificate is missing; key policies are migrated only for complete provisioned state: %v",
				ErrInconsistentMachineState, what, err)
		}
		return nil, nil, fmt.Errorf("read %s certificate: %w", what, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse %s certificate: %v", ErrInconsistentMachineState, what, err)
	}
	return der, cert, nil
}

// verifyKeyForCert opens a key, requires its public key to match cert and
// always releases the handle.
func verifyKeyForCert(open func() (crypto.Signer, error), cert *x509.Certificate, what string) error {
	signer, err := open()
	if err != nil {
		return fmt.Errorf("open %s key: %w", what, err)
	}
	defer closeSigner(signer)
	if err := verifyPublicKeyMatch(cert, signer.Public()); err != nil {
		return fmt.Errorf("%w: %s cert/key mismatch: %v", ErrInconsistentMachineState, what, err)
	}
	return nil
}
