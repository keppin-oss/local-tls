package localtls

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrTrustAnchorNotFound indicates that the exact CA trust anchor is not
// present in the machine trust store (i.e. it is already absent). Cleanup
// treats this as an idempotent success, not a failure.
var ErrTrustAnchorNotFound = errors.New("trust anchor certificate not found in LocalMachine\\Root")

// TrustState describes the result of a runtime trust verification.
type TrustState int

const (
	// TrustHealthy means the expected CA certificate is present exactly once
	// in the machine trust store.
	TrustHealthy TrustState = iota

	// TrustAbsent means the expected CA certificate is not present in the
	// machine trust store. Repair (elevated provisioning) is required.
	TrustAbsent

	// TrustConflict means a certificate with a matching subject name but a
	// different fingerprint exists. Manual resolution is required.
	TrustConflict

	// TrustError means the verification itself failed (store access, etc.).
	TrustError
)

// String returns a human-readable representation of the trust state.
func (s TrustState) String() string {
	switch s {
	case TrustHealthy:
		return "healthy"
	case TrustAbsent:
		return "absent"
	case TrustConflict:
		return "conflict"
	case TrustError:
		return "error"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// TrustProvisioner performs elevated certificate trust operations.
// Mutating operations MUST only be called from an elevated context
// (installer, provisioning, repair). Normal runtime MUST NOT use this.
type TrustProvisioner interface {
	// InstallTrust installs the CA certificate DER into the machine
	// trust store. It is idempotent: if the exact same certificate
	// (matched by SHA-256 fingerprint) already exists, the call
	// succeeds without creating a duplicate.
	InstallTrust(certificateDER []byte) error

	// RemoveTrust removes the exact CA certificate identified by DER
	// from the machine trust store. Only the exact certificate
	// (matched by SHA-256 fingerprint) is removed.
	// Returns ErrTrustAnchorNotFound when the certificate is not present.
	RemoveTrust(certificateDER []byte) error

	// RemoveTrustBySHA256 removes the exact CA certificate identified by
	// its SHA-256 fingerprint from the machine trust store. This is used
	// when the original DER is no longer available (e.g. the state
	// directory was already removed).
	//
	// Removal is by exact 32-byte SHA-256 identity only; no subject/CN
	// matching is performed. Returns ErrTrustAnchorNotFound when the
	// certificate is not present.
	RemoveTrustBySHA256(fp [32]byte) error
}

// TrustVerifier performs read-only trust verification.
// It is safe for normal (non-elevated) runtime use.
type TrustVerifier interface {
	// VerifyTrust checks whether the given CA certificate DER is
	// trusted in the machine trust store. It returns the trust state
	// and, when TrustError, an error describing the failure.
	VerifyTrust(certificateDER []byte) (TrustState, error)

	// IsTrustedSHA256 reports whether a certificate with the given
	// SHA-256 fingerprint is present in the trust store.
	IsTrustedSHA256(fingerprint [32]byte) (bool, error)
}

// TrustStore is the combined interface for backward compatibility.
// New code should use TrustProvisioner and TrustVerifier separately.
type TrustStore interface {
	TrustProvisioner
	TrustVerifier

	// EnsureTrusted installs the CA certificate DER into the trust store
	// if it is not already present.
	// Deprecated: use TrustProvisioner.InstallTrust for elevated operations,
	// and TrustVerifier.VerifyTrust for runtime checks.
	EnsureTrusted(certificateDER []byte) error
}

// ComputeSHA256Fingerprint returns the SHA-256 fingerprint of a DER certificate.
func ComputeSHA256Fingerprint(der []byte) [32]byte {
	return sha256.Sum256(der)
}

// ParseSHA256Fingerprint parses a 64-character hex SHA-256 fingerprint into a
// [32]byte. It accepts surrounding whitespace and is case-insensitive.
func ParseSHA256Fingerprint(hexFP string) ([32]byte, error) {
	var fp [32]byte
	hexFP = strings.TrimSpace(hexFP)
	if len(hexFP) != 64 {
		return fp, fmt.Errorf("fingerprint must be 64 hex characters (32 bytes SHA-256), got %d", len(hexFP))
	}
	decoded, err := hex.DecodeString(hexFP)
	if err != nil {
		return fp, fmt.Errorf("invalid hex fingerprint: %w", err)
	}
	copy(fp[:], decoded)
	return fp, nil
}

// PlatformTrustStore returns the platform-appropriate TrustStore.
// Machine-scoped trust deployment targets LocalMachine\Root on Windows.
func PlatformTrustStore() (TrustStore, error) {
	return platformTrustStore()
}
