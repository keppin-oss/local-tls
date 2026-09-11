//go:build windows

package localtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/local-tls/internal/identity"
)

const testKeyPrefix = identity.TestKeyNamespace

// TestCreateKey creates a persisted CNG test key with the given name using the
// same security path as production keys. The name must stay in the test namespace.
func TestCreateKey(name string) (crypto.Signer, error) {
	if !strings.HasPrefix(name, testKeyPrefix) {
		return nil, fmt.Errorf("test key name must start with %q", testKeyPrefix)
	}
	signer, err := windowscng.LoadOrCreate(name)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// TestOpenKey opens an existing test key as the current principal. This is kept
// intentionally separate from TestCreateKey so the manual proof can test the
// principal's actual KSP access behavior directly.
func TestOpenKey(name string) (crypto.Signer, error) {
	if !strings.HasPrefix(name, testKeyPrefix) {
		return nil, fmt.Errorf("test key name must start with %q", testKeyPrefix)
	}
	signer, err := windowscng.Open(name)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// TestDeleteKey deletes exactly one persisted CNG test key.
func TestDeleteKey(name string) error {
	if !strings.HasPrefix(name, testKeyPrefix) {
		return fmt.Errorf("test key name must start with %q", testKeyPrefix)
	}
	return mapCNGError(windowscng.Delete(name))
}

// TestSignAndVerify proves the actual signing capability of the current
// principal by performing an ECDSA signing operation through crypto.Signer and
// verifying the resulting signature. This is the authoritative LocalService
// allow-test.
func TestSignAndVerify(signer crypto.Signer) error {
	message := []byte(identity.TestSignMessage)
	hash := sha256.Sum256(message)

	sig, err := signer.Sign(nil, hash[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, hash[:], sig) {
		return fmt.Errorf("signature verification failed: signature does not match public key")
	}
	return nil
}
