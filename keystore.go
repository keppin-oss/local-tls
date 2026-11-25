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
// key was not modified. Local-TLS never rewrites a key DACL.
var ErrKeyPolicyMismatch = errors.New("persisted CNG key DACL does not match its Local-TLS key policy")

// ErrPrivilegeRequired indicates that the operation needs a caller running as
// LocalSystem or as an elevated member of BUILTIN\Administrators, and the caller
// is not one or its privilege could not be determined. Opening the CA key, and
// creating or deleting any Local-TLS key, require such a caller. No key was
// opened, created, modified or deleted on that basis.
var ErrPrivilegeRequired = errors.New("operation requires a privileged caller (LocalSystem or elevated Administrators)")

// ErrKeyExists indicates that a create found a persisted key under the exact
// Local-TLS key name. The existing key was not opened, adopted, modified or
// deleted. It does not reserve the name against a concurrent creator: the
// single-writer contract of ProvisionMachine still applies.
var ErrKeyExists = errors.New("persisted CNG key already exists")

// ErrDeleteVerificationFailed indicates that a delete opened the key but did not
// delete it, because a check on the handle it opened did not pass or could not
// be completed: the key is exportable, is not ECDSA P-256, its DACL is not
// exactly the role policy, or its public key is not the expected
// SubjectPublicKeyInfo. It does not prove that the key belongs to someone else.
// Nothing was deleted or modified.
var ErrDeleteVerificationFailed = errors.New("persisted CNG key verification failed before delete; nothing was deleted")

// ErrKeyDeletionNotCompletable indicates that a Local-TLS key was not deleted
// because its recorded identity, the SubjectPublicKeyInfo of the persisted
// certificate (or, during a failed first install, of the key just created), is
// not available or not usable. The key may still exist. Local-TLS never derives
// that identity by opening the key name: the key is left for an authorized
// administrative recovery.
var ErrKeyDeletionNotCompletable = errors.New("key deletion not completable: no recorded key identity")

// MachineKeyStore provides the machine-scoped persisted Local-TLS keys. On
// Windows it is backed by CNG/KSP; on other platforms it is unsupported.
//
// Opening and creating are separate operations. Open* never creates a key;
// Create* never opens or adopts an existing one. Create* is used only by the
// first install. Delete* (MachineKeyDeleter) is part of the store, so that a
// failed first install can delete exactly the keys it created.
//
// The production implementation never returns private-key bytes. Keys are
// identified by stable names and persist across process restarts.
type MachineKeyStore interface {
	// OpenCAKey opens the existing local TLS CA key. It never creates a key.
	// A key that is absent or not accessible returns ErrKeyNotFound, which does
	// not prove absence.
	OpenCAKey() (crypto.Signer, error)

	// OpenServerKey opens the existing local TLS server key. It never creates a
	// key.
	OpenServerKey() (crypto.Signer, error)

	// CreateCAKey creates a new persistent, non-exportable machine-scoped CA
	// key. A key already persisted under the name returns ErrKeyExists and is
	// left untouched.
	//
	// The returned signer carries the new key's identity: its DER
	// SubjectPublicKeyInfo is x509.MarshalPKIXPublicKey(signer.Public()), the
	// value DeleteCAKey expects. A direct caller must record it, before using
	// the key, wherever it can still read it to delete the key later; it must
	// never derive it by reopening the key name. Local-TLS records it in
	// memory right after the create and durably in the CA certificate DER.
	CreateCAKey() (crypto.Signer, error)

	// CreateServerKey creates a new persistent, non-exportable machine-scoped
	// server key. A key already persisted under the name returns ErrKeyExists
	// and is left untouched. Its identity is recorded as for CreateCAKey;
	// Local-TLS keeps it durably in the server certificate DER.
	CreateServerKey() (crypto.Signer, error)

	MachineKeyDeleter
}

// PlatformKeyStore returns the platform-appropriate MachineKeyStore.
// On Windows this uses CNG/KSP with the Microsoft Software Key Storage Provider.
// On other platforms it returns an error — machine-scoped key storage is not
// supported outside Windows.
func PlatformKeyStore() (MachineKeyStore, error) {
	return platformKeyStore()
}

// MachineKeyDeleter deletes exactly the Local-TLS-owned persisted machine keys.
// It deletes only by exact persisted key name, never by wildcard or CN, and
// only after verifying, on the handle it deletes, that the key holds its role
// policy and that its public key is the expected one.
type MachineKeyDeleter interface {
	// DeleteCAKey deletes the exact persisted Local-TLS CA key whose DER
	// SubjectPublicKeyInfo is expectedSPKI. expectedSPKI must come from a
	// record (the persisted CA certificate, or the key just created), never
	// from opening the key name. Returns ErrKeyNotFound when the key was not
	// found or is not accessible (nothing was deleted, absence is not proven)
	// and ErrDeleteVerificationFailed when the verification did not pass.
	DeleteCAKey(expectedSPKI []byte) error

	// DeleteServerKey deletes the exact persisted Local-TLS server key whose
	// DER SubjectPublicKeyInfo is expectedSPKI, with the same rules as
	// DeleteCAKey.
	DeleteServerKey(expectedSPKI []byte) error
}

// PlatformKeyDeleter returns the platform-appropriate MachineKeyDeleter.
// On Windows this deletes the exact persisted CNG keys via the Microsoft
// Software Key Storage Provider. On other platforms it returns an error.
func PlatformKeyDeleter() (MachineKeyDeleter, error) {
	return platformKeyDeleter()
}
