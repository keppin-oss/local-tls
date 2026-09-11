//go:build windows

package localtls

import (
	"crypto"
	"errors"

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

// cngKeyStore implements both MachineKeyStore and MachineKeyDeleter by
// delegating the native Windows CNG/KSP custody (Microsoft Software KSP,
// machine scope, ECDSA P-256, non-exportable, shared DACL, handle lifecycle)
// to the shared github.com/keppin-oss/cng/windowscng package.
//
// This package owns only the Local-TLS policy: the production key names and the
// decision of which semantic key (CA vs server) to create/open/delete.
type cngKeyStore struct{}

func platformKeyStore() (MachineKeyStore, error) {
	return &cngKeyStore{}, nil
}

func platformKeyDeleter() (MachineKeyDeleter, error) {
	return &cngKeyStore{}, nil
}

func (ks *cngKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	return loadOrCreateKey(caKeyName)
}

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
// CNG layer, preserving Local-TLS semantics (Microsoft Software KSP, machine
// scope, ECDSA P-256, non-exportable, shared DACL).
func loadOrCreateKey(name string) (crypto.Signer, error) {
	signer, err := windowscng.LoadOrCreate(name)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// openProductionKey opens an existing persisted CNG production key by name and
// never creates a replacement. It fails if the key does not exist or is
// inaccessible. Delegates to the shared CNG layer.
func openProductionKey(name string) (crypto.Signer, error) {
	signer, err := windowscng.Open(name)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// deleteProductionKey deletes exactly one persisted production CNG key by name.
// It never creates a key and never performs wildcard/prefix deletion. Returns
// ErrKeyNotFound when the exact key does not exist (idempotent cleanup).
func deleteProductionKey(name string) error {
	return mapCNGError(windowscng.Delete(name))
}

// mapCNGError translates the shared windowscng missing-key sentinel into the
// Local-TLS ErrKeyNotFound contract so callers never need to know windowscng's
// sentinel. Permission, corruption, incompatible-key, ACL, and other unexpected
// failures are passed through unchanged and are never converted into
// not-found.
func mapCNGError(err error) error {
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		return ErrKeyNotFound
	}
	return err
}
