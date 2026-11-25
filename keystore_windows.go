//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/local-tls/internal/identity"
)

// Key names for CNG persisted keys.
//
// These are production key identities owned by Local TLS. They MUST NOT
// move into CNG: the shared package operates only on exact caller
// supplied names and never owns, invents, or references any Keppin key name.
const (
	caKeyName     = identity.ProdCAKeyName
	serverKeyName = identity.ProdServerKeyName
)

// keyPolicy returns the CNG access policy of a production key role:
//
//   - CA key: windowscng.PolicyPrivilegedOnly, D:P(A;;GA;;;SY)(A;;GA;;;BA).
//     Only LocalSystem and elevated Administrators can open it; a LOCAL SERVICE
//     runtime never can.
//   - server key: windowscng.PolicyServiceSigner,
//     D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS), so the non-elevated Agent
//     running as LOCAL SERVICE can open it and sign TLS handshakes.
//
// Any other name is rejected: Local-TLS never opens, creates or deletes a
// production key without an explicit role policy.
func keyPolicy(name string) (windowscng.Policy, error) {
	switch name {
	case caKeyName:
		return windowscng.PolicyPrivilegedOnly, nil
	case serverKeyName:
		return windowscng.PolicyServiceSigner, nil
	default:
		return 0, fmt.Errorf("no Local-TLS key policy for key name %q", name)
	}
}

// cngKeyAPI is the seam between Local-TLS and windowscng. It is typed on the
// concrete windowscng.Policy, although windowscng accepts any KeyPolicy, so
// Local-TLS can only pass one of its two role policies. Production uses
// nativeCNGKeyAPI; unit tests pass fakes to the *With functions so no machine
// key is touched.
type cngKeyAPI struct {
	open   func(name string, p windowscng.Policy) (windowscng.Signer, error)
	create func(name string, p windowscng.Policy) (windowscng.Signer, error)
	delete func(name string, p windowscng.Policy, expectedSPKI []byte) error
}

var nativeCNGKeyAPI = cngKeyAPI{
	open: func(name string, p windowscng.Policy) (windowscng.Signer, error) {
		return windowscng.Open(name, p)
	},
	create: func(name string, p windowscng.Policy) (windowscng.Signer, error) {
		return windowscng.Create(name, p)
	},
	delete: func(name string, p windowscng.Policy, expectedSPKI []byte) error {
		return windowscng.Delete(name, p, expectedSPKI)
	},
}

// cngKeyStore implements both MachineKeyStore and MachineKeyDeleter by
// delegating the native Windows CNG/KSP custody (Microsoft Software KSP,
// machine scope, ECDSA P-256, non-exportable, per-role DACL policy, handle
// lifecycle) to the shared github.com/keppin-oss/cng/windowscng package.
//
// This package owns only the Local-TLS policy: the production key names, the
// access policy of each key role (see keyPolicy) and the decision of which
// semantic key (CA vs server) to open, create or delete.
type cngKeyStore struct{}

func platformKeyStore() (MachineKeyStore, error) {
	return &cngKeyStore{}, nil
}

func platformKeyDeleter() (MachineKeyDeleter, error) {
	return &cngKeyStore{}, nil
}

// OpenCAKey opens the existing CA key under PolicyPrivilegedOnly. It never
// creates a key. A non-privileged caller gets ErrPrivilegeRequired; an existing
// key with another DACL gets ErrKeyPolicyMismatch and is not modified.
func (ks *cngKeyStore) OpenCAKey() (crypto.Signer, error) {
	return openProductionKey(caKeyName)
}

// OpenServerKey opens the existing server key under PolicyServiceSigner. It
// never creates a key.
func (ks *cngKeyStore) OpenServerKey() (crypto.Signer, error) {
	return openProductionKey(serverKeyName)
}

// CreateCAKey creates the CA key under PolicyPrivilegedOnly. An existing key
// returns ErrKeyExists and is not opened, adopted or modified.
func (ks *cngKeyStore) CreateCAKey() (crypto.Signer, error) {
	return createProductionKey(caKeyName)
}

// CreateServerKey creates the server key under PolicyServiceSigner. An
// existing key returns ErrKeyExists and is not opened, adopted or modified.
func (ks *cngKeyStore) CreateServerKey() (crypto.Signer, error) {
	return createProductionKey(serverKeyName)
}

// DeleteCAKey deletes exactly the persisted Local-TLS CA key whose
// SubjectPublicKeyInfo is expectedSPKI.
func (ks *cngKeyStore) DeleteCAKey(expectedSPKI []byte) error {
	return deleteProductionKey(caKeyName, expectedSPKI)
}

// DeleteServerKey deletes exactly the persisted Local-TLS server key whose
// SubjectPublicKeyInfo is expectedSPKI.
func (ks *cngKeyStore) DeleteServerKey(expectedSPKI []byte) error {
	return deleteProductionKey(serverKeyName, expectedSPKI)
}

// openProductionKey opens an existing persisted CNG production key by name
// under its role policy and never creates a replacement. It fails if the key
// does not exist or is inaccessible (ErrKeyNotFound), if its DACL is not
// exactly the role policy (ErrKeyPolicyMismatch), or, for the CA key, if the
// caller is not privileged (ErrPrivilegeRequired, before any open).
func openProductionKey(name string) (crypto.Signer, error) {
	return openProductionKeyWith(nativeCNGKeyAPI, name)
}

func openProductionKeyWith(api cngKeyAPI, name string) (crypto.Signer, error) {
	policy, err := keyPolicy(name)
	if err != nil {
		return nil, err
	}
	signer, err := api.open(name, policy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// createProductionKey creates a new persisted CNG production key by name under
// its role policy. It never opens or adopts an existing key: a key already
// persisted under the name returns ErrKeyExists. Creation requires a privileged
// caller (ErrPrivilegeRequired). When the created key fails its post-create
// checks, windowscng deletes it through the same handle; if that delete fails
// too, the error also matches windowscng.ErrCleanupFailed and the key may
// persist. The caller never owns a signer on error and must not delete again.
func createProductionKey(name string) (crypto.Signer, error) {
	return createProductionKeyWith(nativeCNGKeyAPI, name)
}

func createProductionKeyWith(api cngKeyAPI, name string) (crypto.Signer, error) {
	policy, err := keyPolicy(name)
	if err != nil {
		return nil, err
	}
	signer, err := api.create(name, policy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// deleteProductionKey deletes exactly one persisted production CNG key by name
// after windowscng has verified, on the handle it deletes, the role policy and
// that the public key is expectedSPKI. It never creates a key and never
// performs wildcard/prefix deletion. An empty or malformed expectedSPKI is
// rejected before any native call. ErrKeyNotFound means that nothing was
// deleted, not that the key is absent.
func deleteProductionKey(name string, expectedSPKI []byte) error {
	return deleteProductionKeyWith(nativeCNGKeyAPI, name, expectedSPKI)
}

func deleteProductionKeyWith(api cngKeyAPI, name string, expectedSPKI []byte) error {
	policy, err := keyPolicy(name)
	if err != nil {
		return err
	}
	return mapCNGError(api.delete(name, policy, expectedSPKI))
}

// mapCNGError translates the shared windowscng sentinels into the Local-TLS
// contract, keeping the windowscng error in the chain so that its sentinels
// and native *windowscng.NCryptError stay reachable:
//
//   - verification before a delete failed → ErrDeleteVerificationFailed (it
//     takes precedence over a policy mismatch, which it may also carry);
//   - create found an existing key → ErrKeyExists;
//   - not found or not accessible → ErrKeyNotFound;
//   - DACL not in the role policy → ErrKeyPolicyMismatch;
//   - privileged caller required → ErrPrivilegeRequired.
//
// Invalid input, permission, corruption, incompatible-key, native delete and
// other unexpected failures are passed through unchanged and are never
// converted into not-found.
func mapCNGError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windowscng.ErrDeleteVerificationFailed):
		return fmt.Errorf("%w: %w", ErrDeleteVerificationFailed, err)
	case errors.Is(err, windowscng.ErrKeyExists):
		return fmt.Errorf("%w: %w", ErrKeyExists, err)
	case errors.Is(err, windowscng.ErrKeyNotFound):
		return fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	case errors.Is(err, windowscng.ErrPolicyMismatch):
		return fmt.Errorf("%w: %w", ErrKeyPolicyMismatch, err)
	case errors.Is(err, windowscng.ErrPrivilegeRequired):
		return fmt.Errorf("%w: %w", ErrPrivilegeRequired, err)
	default:
		return err
	}
}
