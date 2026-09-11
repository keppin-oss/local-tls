package localtls

import "fmt"

// Protector transforms sensitive material for at-rest persistence on the legacy
// exported-key provisioning path. The production machine path does not use
// Protector: it keeps private keys in CNG/KSP and persists only public
// certificate DER. Protector is a seam — this package does not define which
// implementation (if any) actually encrypts the bytes it receives.
type Protector interface {
	Protect(plaintext []byte) ([]byte, error)
	Unprotect(ciphertext []byte) ([]byte, error)
}

// PlatformProtector returns the platform-appropriate Protector. Machine-scoped
// key protection is not configured: the production machine path uses CNG/KSP key
// custody rather than the protector-based path, so this function returns an
// error.
func PlatformProtector() (Protector, error) {
	return nil, fmt.Errorf("machine key protector not configured; the production machine path uses CNG/KSP key custody")
}
