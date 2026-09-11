package localtls

import (
	"crypto"
	"errors"
)

// ErrKeyNotFound indicates that the exact persisted CNG key does not exist.
// Cleanup treats this as an idempotent success, not a failure.
var ErrKeyNotFound = errors.New("persisted CNG key not found")

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
	// Returns ErrKeyNotFound when the key does not exist.
	DeleteCAKey() error

	// DeleteServerKey deletes the exact persisted Local-TLS server key.
	// Returns ErrKeyNotFound when the key does not exist.
	DeleteServerKey() error
}

// PlatformKeyDeleter returns the platform-appropriate MachineKeyDeleter.
// On Windows this deletes the exact persisted CNG keys via the Microsoft
// Software Key Storage Provider. On other platforms it returns an error.
func PlatformKeyDeleter() (MachineKeyDeleter, error) {
	return platformKeyDeleter()
}
