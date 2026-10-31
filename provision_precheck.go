package localtls

import (
	"errors"
	"fmt"
	"path/filepath"
)

// provisionPreCheck decides whether production provisioning may proceed into
// ProvisionWithKeyStore, which treats a missing CA certificate DER as a first
// install and issues a new CA certificate.
//
// Issuing a new CA certificate should happen only when no CA key exists: a CA
// key that survived without its certificate would be certified again under a
// new fingerprint, i.e. a second trust anchor. A failed key open is not proof
// of absence: ErrKeyNotFound means "not found or not accessible", and any
// other open error says nothing about whether the key exists. Therefore, when
// the CA DER in tlsDir is missing, provisionPreCheck:
//   - fails closed when the server DER exists without the CA DER;
//   - fails closed when the CA key opens (existing key, missing certificate);
//     both of these return an error wrapping ErrInconsistentMachineState;
//   - fails closed on any CA key open error other than ErrKeyNotFound;
//   - on ErrKeyNotFound, fails closed for a caller that is not privileged
//     (SYSTEM or elevated Administrators) or whose privilege cannot be
//     determined, and otherwise lets the first install proceed.
//
// The last case is a conservative gate, not a proof of absence: the expected
// key DACL grants these principals full access, but ErrKeyNotFound stays
// ambiguous for them too (for example a key with a foreign DACL). The decision
// is also not atomic with the later open-or-create, so a key created or
// re-permissioned by another actor in between can still be certified; callers
// must uphold the single-writer contract documented on ProvisionMachine.
//
// When the CA DER exists, the check returns nil without consulting the key or
// the caller's privilege, and provisioning continues through
// ProvisionWithKeyStore, which verifies the existing state and fails closed
// with ErrInconsistentMachineState when the server DER is missing (it never
// reissues the CA certificate). A DER whose presence cannot be determined (a
// stat error other than not-exist, for example access denied) is never treated
// as absent: the check fails closed. probeKey opens the exact named key
// without creating it and releases it. provisionPreCheck never creates,
// deletes, resets or regenerates a key.
func provisionPreCheck(tlsDir, caKey string, probeKey func(name string) error, isPrivileged func() (bool, error)) error {
	caExists, err := osFS.statExists(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return fmt.Errorf("%w: cannot determine whether the CA certificate exists; refusing first install: %v", ErrInconsistentMachineState, err)
	}
	if caExists {
		return nil
	}

	serverExists, err := osFS.statExists(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return fmt.Errorf("%w: cannot determine whether the server certificate exists; refusing first install: %v", ErrInconsistentMachineState, err)
	}
	if serverExists {
		return fmt.Errorf(
			"%w: the server certificate exists but the CA certificate is missing in %s — "+
				"automatic CA regeneration is forbidden to prevent duplicate trust anchors; "+
				"restore the certificate material or perform a full re-provisioning cleanup",
			ErrInconsistentMachineState, tlsDir,
		)
	}

	err = probeKey(caKey)
	if err == nil {
		return fmt.Errorf(
			"%w: a CNG key %q exists but the CA certificate is missing or corrupt in %s — "+
				"automatic CA regeneration is forbidden to prevent duplicate trust anchors; "+
				"restore the certificate material or perform a full re-provisioning cleanup",
			ErrInconsistentMachineState, caKey, tlsDir,
		)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("cannot determine whether CA key %q exists; refusing first install: %w", caKey, err)
	}

	privileged, privErr := isPrivileged()
	if privErr != nil {
		return fmt.Errorf("cannot determine caller privilege; refusing first install while CA key %q is not found or not accessible: %w", caKey, errors.Join(privErr, err))
	}
	if !privileged {
		return fmt.Errorf("CA key %q is not found or not accessible to a non-privileged caller, so its absence is not established; run provisioning elevated (Administrator): %w", caKey, err)
	}
	return nil
}
