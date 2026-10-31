package localtls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrCertificateNotValidNow indicates that the CA or the server
	// certificate is expired or not yet valid at the time of the check.
	ErrCertificateNotValidNow = errors.New("certificate is expired or not yet valid")

	// ErrLeafOutlivesCA indicates that a server certificate's validity would
	// extend beyond its CA certificate's NotAfter. Local-TLS never shortens
	// the leaf to fit and never renews or rotates the CA automatically.
	ErrLeafOutlivesCA = errors.New("server certificate validity extends beyond the CA certificate")

	// ErrTrustNotHealthy indicates that the CA trust anchor is not in the
	// TrustHealthy state (absent or conflicting). Loading fails closed;
	// manual resolution is required.
	ErrTrustNotHealthy = errors.New("CA trust anchor is not healthy")

	// ErrInconsistentMachineState indicates persisted Local-TLS state that
	// cannot be used or repaired automatically, for example a CA certificate
	// DER without a server certificate DER. Nothing is regenerated.
	ErrInconsistentMachineState = errors.New("inconsistent Local-TLS machine state")
)

// validateCA checks the CA certificate's structure and that it is valid at now.
//
// Certificate validity here and in validateServerLeaf is inclusive at the
// encoded NotBefore and NotAfter instants, as in RFC 5280 and crypto/x509: now
// equal to either bound is valid, one nanosecond outside is not.
func validateCA(ca *x509.Certificate, now time.Time) error {
	if !ca.IsCA || !ca.BasicConstraintsValid {
		return fmt.Errorf("CA certificate is not a CA")
	}
	if now.Before(ca.NotBefore) || now.After(ca.NotAfter) {
		return fmt.Errorf("%w: CA certificate valid %s to %s, now %s", ErrCertificateNotValidNow,
			ca.NotBefore.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// validateServerIdentity checks the time-independent identity of a server
// certificate: key match, issuer signature, exact SANs and the server-auth EKU.
// It is used on its own only to accept an expired previous leaf as the base of
// a renewal; serving and candidates also require validateServerLeaf.
func validateServerIdentity(leaf, ca *x509.Certificate, serverPub crypto.PublicKey) error {
	if err := verifyPublicKeyMatch(leaf, serverPub); err != nil {
		return fmt.Errorf("server cert/key mismatch: %w", err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("server certificate was not issued by our CA: %w", err)
	}
	if err := validateSAN(leaf); err != nil {
		return err
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return fmt.Errorf("server certificate extended key usage must be exactly [serverAuth]")
	}
	return nil
}

// validateServerLeaf is the common validator for serving material and renewal
// candidates. Beyond validateServerIdentity and validateCA it requires the leaf
// to be valid at now, its NotAfter not to exceed the CA's NotAfter, and a full
// chain verification to the explicit CA root for "localhost" with the
// server-auth EKU. The explicit NotAfter comparison is required because
// chain verification at now does not compare the two expiries.
func validateServerLeaf(leaf, ca *x509.Certificate, serverPub crypto.PublicKey, now time.Time) error {
	if err := validateCA(ca, now); err != nil {
		return err
	}
	if err := validateServerIdentity(leaf, ca, serverPub); err != nil {
		return err
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: server certificate valid %s to %s, now %s", ErrCertificateNotValidNow,
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if leaf.NotAfter.After(ca.NotAfter) {
		return fmt.Errorf("%w: server NotAfter %s, CA NotAfter %s", ErrLeafOutlivesCA,
			leaf.NotAfter.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339))
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "localhost",
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("server certificate chain verification: %w", err)
	}
	return nil
}

// requireTrustHealthy performs read-only trust verification and fails closed
// unless the state is TrustHealthy.
func requireTrustHealthy(verifier TrustVerifier, caDER []byte) error {
	state, err := verifier.VerifyTrust(caDER)
	if err != nil {
		return fmt.Errorf("verify CA trust: %w", err)
	}
	if state != TrustHealthy {
		return fmt.Errorf("%w: trust state is %s (manual resolution required)", ErrTrustNotHealthy, state)
	}
	return nil
}

// renewalDue reports whether the server certificate is within
// RenewalThreshold of expiry or already expired.
func renewalDue(leaf *x509.Certificate, now time.Time) bool {
	return now.After(leaf.NotAfter) || leaf.NotAfter.Sub(now) <= RenewalThreshold
}
