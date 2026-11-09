package localtls

import (
	"crypto"
	"errors"
)

// ErrKeyNotFound indicates that the native open of the exact persisted CNG key
// reported the key as not found OR not accessible to the caller (NTE_NOT_FOUND
// or NTE_BAD_KEYSET). It does not prove that the key is absent: the Microsoft
// Software KSP reports NTE_BAD_KEYSET to a caller that the key's DACL does not
// grant. It must never by itself trigger a reset, regeneration or overwrite of
// a key, and cleanup never treats it as a confirmed deletion (see
// ErrKeyDeletionUnconfirmed). The returned error keeps the native HRESULT in
// its message.
var ErrKeyNotFound = errors.New("persisted CNG key not found or not accessible")

// ErrKeyPolicyMismatch indicates that a persisted Local-TLS key exists but its
// DACL is not exactly the one required for its role: the CA key must be
// privileged-only (SYSTEM and Administrators) and the server key must be the
// service-signer DACL (SYSTEM, Administrators, LOCAL SERVICE read/execute). The
// key was not modified. A CA key provisioned by an earlier release still
// carries the service-signer DACL and fails this way until an elevated caller
// runs MigrateMachineKeyPolicies; Local-TLS never migrates a key implicitly.
var ErrKeyPolicyMismatch = errors.New("persisted CNG key DACL does not match its Local-TLS key policy")

// ErrPrivilegeRequired indicates that the operation needs a caller running as
// LocalSystem or as an elevated member of BUILTIN\Administrators, and the caller
// is not one or its privilege could not be determined. Opening or creating the
// CA key, and MigrateMachineKeyPolicies, require such a caller. No key was
// opened, created or modified on that basis.
var ErrPrivilegeRequired = errors.New("operation requires a privileged caller (LocalSystem or elevated Administrators)")

// MachineKeyStore provides machine-scoped persistent signing keys.
// On Windows this is backed by CNG/KSP; on other platforms it is unsupported.
//
// The production implementation never returns private-key bytes.
// Keys are identified by stable names and persist across process restarts.
type MachineKeyStore interface {
	// LoadOrCreateCAKey returns a signer for the local TLS CA key.
	// If the key does not exist it is created as a persistent,
	// non-exportable machine-scoped key.
	LoadOrCreateCAKey() (crypto.Signer, error)

	// LoadOrCreateServerKey returns a signer for the local TLS server key.
	// If the key does not exist it is created as a persistent,
	// non-exportable machine-scoped key.
	LoadOrCreateServerKey() (crypto.Signer, error)
}

// PlatformKeyStore returns the platform-appropriate MachineKeyStore.
// On Windows this uses CNG/KSP with the Microsoft Software Key Storage Provider.
// On other platforms it returns an error — machine-scoped key storage is not
// supported outside Windows.
func PlatformKeyStore() (MachineKeyStore, error) {
	return platformKeyStore()
}

// MachineKeyDeleter deletes exactly the Local-TLS-owned persisted machine keys.
// It must never delete keys that are not owned by this module, and it deletes
// only by exact persisted key name — never by wildcard or CN.
type MachineKeyDeleter interface {
	// DeleteCAKey deletes the exact persisted Local-TLS CA key.
	// Returns ErrKeyNotFound when the key was not found or is not
	// accessible: nothing was deleted, and absence is not proven.
	DeleteCAKey() error

	// DeleteServerKey deletes the exact persisted Local-TLS server key.
	// Returns ErrKeyNotFound when the key was not found or is not
	// accessible: nothing was deleted, and absence is not proven.
	DeleteServerKey() error
}

// PlatformKeyDeleter returns the platform-appropriate MachineKeyDeleter.
// On Windows this deletes the exact persisted CNG keys via the Microsoft
// Software Key Storage Provider. On other platforms it returns an error.
func PlatformKeyDeleter() (MachineKeyDeleter, error) {
	return platformKeyDeleter()
}
