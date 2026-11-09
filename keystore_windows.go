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
// Any other name is rejected: Local-TLS never opens or creates a production
// key without an explicit role policy.
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

// cngPolicyAPI is the seam between Local-TLS and the policy-aware windowscng
// functions. Production uses nativeCNGPolicyAPI; unit tests pass fakes to the
// *With functions so no machine key is touched.
type cngPolicyAPI struct {
	open         func(name string, p windowscng.Policy) (windowscng.Signer, error)
	loadOrCreate func(name string, p windowscng.Policy) (windowscng.Signer, error)
	apply        func(name string, p windowscng.Policy) error
}

var nativeCNGPolicyAPI = cngPolicyAPI{
	open:         windowscng.OpenWithPolicy,
	loadOrCreate: windowscng.LoadOrCreateWithPolicy,
	apply:        windowscng.ApplyPolicy,
}

// cngKeyStore implements both MachineKeyStore and MachineKeyDeleter by
// delegating the native Windows CNG/KSP custody (Microsoft Software KSP,
// machine scope, ECDSA P-256, non-exportable, per-role DACL policy, handle
// lifecycle) to the shared github.com/keppin-oss/cng/windowscng package.
//
// This package owns only the Local-TLS policy: the production key names, the
// access policy of each key role (see keyPolicy) and the decision of which
// semantic key (CA vs server) to create/open/delete.
type cngKeyStore struct{}

func platformKeyStore() (MachineKeyStore, error) {
	return &cngKeyStore{}, nil
}

func platformKeyDeleter() (MachineKeyDeleter, error) {
	return &cngKeyStore{}, nil
}

// LoadOrCreateCAKey opens the CA key under PolicyPrivilegedOnly, or creates it
// with that policy only when the native open reports it absent to a privileged
// caller. A non-privileged caller gets ErrPrivilegeRequired; an existing key
// with another DACL gets ErrKeyPolicyMismatch and is not modified.
func (ks *cngKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	return loadOrCreateKey(caKeyName)
}

// LoadOrCreateServerKey opens the server key under PolicyServiceSigner, or
// creates it with that policy only when the native open reports it absent to a
// privileged caller.
func (ks *cngKeyStore) LoadOrCreateServerKey() (crypto.Signer, error) {
	return loadOrCreateKey(serverKeyName)
}

// DeleteCAKey deletes exactly the persisted Local-TLS CA key.
func (ks *cngKeyStore) DeleteCAKey() error {
	return deleteProductionKey(caKeyName)
}

// DeleteServerKey deletes exactly the persisted Local-TLS server key.
func (ks *cngKeyStore) DeleteServerKey() error {
	return deleteProductionKey(serverKeyName)
}

// loadOrCreateKey delegates the exact named key open-or-create to the shared
// CNG layer under the key's role policy. Unlike the legacy
// windowscng.LoadOrCreate, creation is attempted only when the native open
// reports "not found" to a privileged caller; any other open failure, and an
// existing key in another policy state, is returned without creating or
// modifying a key.
func loadOrCreateKey(name string) (crypto.Signer, error) {
	return loadOrCreateKeyWith(nativeCNGPolicyAPI, name)
}

func loadOrCreateKeyWith(api cngPolicyAPI, name string) (crypto.Signer, error) {
	policy, err := keyPolicy(name)
	if err != nil {
		return nil, err
	}
	signer, err := api.loadOrCreate(name, policy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// openProductionKey opens an existing persisted CNG production key by name
// under its role policy and never creates a replacement. It fails if the key
// does not exist or is inaccessible (ErrKeyNotFound), if its DACL is not
// exactly the role policy (ErrKeyPolicyMismatch), or, for the CA key, if the
// caller is not privileged (ErrPrivilegeRequired, before any open).
func openProductionKey(name string) (crypto.Signer, error) {
	return openProductionKeyWith(nativeCNGPolicyAPI, name)
}

func openProductionKeyWith(api cngPolicyAPI, name string) (crypto.Signer, error) {
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

// tightenCAKeyPolicy brings the existing CA key to PolicyPrivilegedOnly in
// place through windowscng.ApplyPolicy: idempotent when already privileged-only,
// otherwise permitted only from the exact service-signer DACL, with read-back
// on the open handle and on a fresh handle and no rollback. It never creates,
// rotates or deletes the key. Used only by MigrateMachineKeyPolicies.
func tightenCAKeyPolicy() error {
	return tightenCAKeyPolicyWith(nativeCNGPolicyAPI)
}

func tightenCAKeyPolicyWith(api cngPolicyAPI) error {
	policy, err := keyPolicy(caKeyName)
	if err != nil {
		return err
	}
	return mapCNGError(api.apply(caKeyName, policy))
}

// deleteProductionKey deletes exactly one persisted production CNG key by name.
// It never creates a key and never performs wildcard/prefix deletion. Returns
// ErrKeyNotFound when the exact key was not found or is not accessible; that
// means nothing was deleted, not that the key is absent. Deletion does not
// depend on the key's DACL policy.
func deleteProductionKey(name string) error {
	return mapCNGError(windowscng.Delete(name))
}

// mapCNGError translates the shared windowscng sentinels into the Local-TLS
// contract so callers never need to know windowscng's sentinels:
//
//   - not found or not accessible → ErrKeyNotFound (the shared error's message,
//     with the key name and native HRESULT, is kept; the shared sentinel is not);
//   - DACL not in the role policy → ErrKeyPolicyMismatch;
//   - privileged caller required → ErrPrivilegeRequired.
//
// For the last two the shared error stays in the chain (for example
// windowscng.ErrCleanupFailed after a failed creation). Permission, corruption,
// incompatible-key and other unexpected failures are passed through unchanged
// and are never converted into not-found.
func mapCNGError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windowscng.ErrKeyNotFound):
		return fmt.Errorf("%w: %s", ErrKeyNotFound, err)
	case errors.Is(err, windowscng.ErrPolicyMismatch):
		return fmt.Errorf("%w: %w", ErrKeyPolicyMismatch, err)
	case errors.Is(err, windowscng.ErrPrivilegeRequired):
		return fmt.Errorf("%w: %w", ErrPrivilegeRequired, err)
	default:
		return err
	}
}
