//go:build windows

package localtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/local-tls/internal/identity"
)

const testKeyPrefix = identity.TestKeyNamespace

// testKeyPolicy is the DACL of every Keppin.Test.* key: the service-signer
// policy, so that a LOCAL SERVICE process can open the key and sign. It is not
// the per-role policy of the production keys (the CA key is privileged-only).
const testKeyPolicy = windowscng.PolicyServiceSigner

func checkTestKeyName(name string) error {
	if !strings.HasPrefix(name, testKeyPrefix) {
		return fmt.Errorf("test key name must start with %q", testKeyPrefix)
	}
	return nil
}

// TestCreateKey creates a new persisted CNG test key with the given name under
// the service-signer policy. It never opens or adopts an existing key: a key
// already persisted under the name returns ErrKeyExists. It requires a
// privileged caller. The name must stay in the test namespace. The caller must
// record the key's SubjectPublicKeyInfo (TestKeySPKI) to delete it later.
func TestCreateKey(name string) (crypto.Signer, error) {
	if err := checkTestKeyName(name); err != nil {
		return nil, err
	}
	signer, err := windowscng.Create(name, testKeyPolicy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// TestOpenKey opens an existing test key as the current principal under the
// service-signer policy. It never creates a key. This is kept intentionally
// separate from TestCreateKey so the manual proof can test the principal's
// actual KSP access behavior directly.
func TestOpenKey(name string) (crypto.Signer, error) {
	if err := checkTestKeyName(name); err != nil {
		return nil, err
	}
	signer, err := windowscng.Open(name, testKeyPolicy)
	if err != nil {
		return nil, mapCNGError(err)
	}
	return signer, nil
}

// TestDeleteKey deletes exactly one persisted CNG test key, after verifying on
// the handle it deletes that the key holds the service-signer policy and that
// its DER SubjectPublicKeyInfo is expectedSPKI. expectedSPKI must be the value
// recorded when the key was created, never one read by opening the key.
func TestDeleteKey(name string, expectedSPKI []byte) error {
	if err := checkTestKeyName(name); err != nil {
		return err
	}
	return mapCNGError(windowscng.Delete(name, testKeyPolicy, expectedSPKI))
}

// TestKeySPKI returns the DER SubjectPublicKeyInfo of a signer, the identity
// TestDeleteKey expects.
func TestKeySPKI(signer crypto.Signer) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("encode the test key public key: %w", err)
	}
	return spki, nil
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
