//go:build windows

package localtls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProvisionMachine provisions or repairs the production machine TLS material.
//
// MUST be run elevated (Administrator). It:
//   - creates or opens machine-scoped persisted CNG keys (CA + server)
//   - generates self-signed CA and CA-signed server certificates
//   - persists only public certificate DERs to disk (no private-key files)
//   - installs the CA certificate in LocalMachine\Root (idempotent)
//
// ProvisionMachine never returns private-key bytes. Keys are identified by
// stable names and persist in the Microsoft Software KSP across process
// restarts.
//
// Repeated provisioning with the same persisted keys is idempotent: the same
// CA identity (fingerprint) is preserved and the CA certificate is not
// re-installed if already present. The server certificate is only renewed
// when near or past expiry.
func ProvisionMachine() (Material, error) {
	root, err := MachineAgentPath()
	if err != nil {
		return Material{}, fmt.Errorf("resolve machine agent path: %w", err)
	}

	keyStore, err := PlatformKeyStore()
	if err != nil {
		return Material{}, fmt.Errorf("platform key store: %w", err)
	}

	trustStore, err := PlatformTrustStore()
	if err != nil {
		return Material{}, fmt.Errorf("platform trust store: %w", err)
	}

	// Pre-provision safety check: fail closed on any partial or incoherent
	// pre-existing production state (a missing/corrupt certificate, a missing or
	// unopenable persisted key, etc.) rather than silently regenerating the CA
	// trust anchor or creating replacement keys. The check is open-only.
	inconsistent, err := checkInconsistentMachineState(root, openProductionKey)
	if err != nil {
		return Material{}, fmt.Errorf("provision pre-check: %w", err)
	}
	if inconsistent {
		return Material{}, fmt.Errorf(
			"inconsistent machine state: existing production material is incomplete or incoherent in %s — "+
				"automatic CA regeneration is forbidden to prevent duplicate trust anchors; "+
				"restore the missing material or perform a full re-provisioning cleanup",
			filepath.Join(root, tlsSubDir),
		)
	}

	return ProvisionWithKeyStore(root, keyStore, trustStore, time.Now)
}

// ReloadMachine loads existing production machine TLS material for normal runtime.
//
// ReloadMachine is safe for non-elevated use. It:
//   - loads existing CA and server certificate DERs from disk
//   - opens (does NOT create) persisted machine-scoped CNG keys
//   - verifies cert ↔ KSP public key match for both CA and server
//   - verifies the server certificate was issued by the CA
//   - validates server certificate SANs (localhost / 127.0.0.1 / ::1)
//   - performs read-only trust verification through TrustVerifier
//   - renews the server certificate if near/past expiry (reuses existing KSP key)
//
// ReloadMachine never mutates LocalMachine\Root. If the CA trust anchor is
// missing or a conflicting certificate exists, ReloadMachine fails closed —
// elevated provisioning/repair is required.
func ReloadMachine() (Material, error) {
	root, err := MachineAgentPath()
	if err != nil {
		return Material{}, fmt.Errorf("resolve machine agent path: %w", err)
	}
	tlsDir := filepath.Join(root, tlsSubDir)

	// Load CA certificate from disk.
	caCertDER, err := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return Material{}, fmt.Errorf("read CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return Material{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Open (do not create) the persisted CA key in CNG.
	caSigner, err := openProductionKey(caKeyName)
	if err != nil {
		return Material{}, fmt.Errorf("open CA key: %w", err)
	}

	// Verify CA cert public key matches the CNG key.
	if err := verifyPublicKeyMatch(caCert, caSigner.Public()); err != nil {
		closeProductionSigner(caSigner)
		return Material{}, fmt.Errorf("CA cert/key mismatch: %w", err)
	}

	// Load server certificate from disk.
	serverCertDER, err := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		closeProductionSigner(caSigner)
		return Material{}, fmt.Errorf("read server certificate: %w", err)
	}
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		closeProductionSigner(caSigner)
		return Material{}, fmt.Errorf("parse server certificate: %w", err)
	}

	// Open (do not create) the persisted server key in CNG.
	serverSigner, err := openProductionKey(serverKeyName)
	if err != nil {
		closeProductionSigner(caSigner)
		return Material{}, fmt.Errorf("open server key: %w", err)
	}

	// Verify server cert public key matches the CNG key.
	if err := verifyPublicKeyMatch(serverCert, serverSigner.Public()); err != nil {
		closeProductionSigner(caSigner)
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("server cert/key mismatch: %w", err)
	}

	// Verify server certificate was issued by our CA.
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		closeProductionSigner(caSigner)
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("server certificate was not issued by our CA: %w", err)
	}

	// Validate SAN.
	if err := validateSAN(serverCert); err != nil {
		closeProductionSigner(caSigner)
		closeProductionSigner(serverSigner)
		return Material{}, err
	}

	// Read-only trust verification — never mutates Root.
	trustStore, err := PlatformTrustStore()
	if err != nil {
		closeProductionSigner(caSigner)
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("platform trust store: %w", err)
	}
	state, trustErr := trustStore.VerifyTrust(caCert.Raw)
	if trustErr != nil {
		closeProductionSigner(caSigner)
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("verify CA trust: %w", trustErr)
	}
	if state != TrustHealthy {
		closeProductionSigner(caSigner)
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("CA not trusted: trust state is %s (elevated provisioning/repair required)", state)
	}

	// Check server certificate renewal.
	needsRenewal := false
	nowTime := time.Now()
	if nowTime.After(serverCert.NotAfter) || serverCert.NotAfter.Sub(nowTime) <= RenewalThreshold {
		needsRenewal = true
	}
	if needsRenewal {
		newServerCert, err := generateServerCertWithSigner(nowTime, caCert, caSigner, serverSigner)
		if err != nil {
			closeProductionSigner(caSigner)
			closeProductionSigner(serverSigner)
			return Material{}, fmt.Errorf("renew server certificate: %w", err)
		}
		if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), newServerCert.Raw, 0600); err != nil {
			closeProductionSigner(caSigner)
			closeProductionSigner(serverSigner)
			return Material{}, err
		}
		serverCert = newServerCert
	}

	// The CA signer is a transient internal handle (used only for issuer and
	// renewal signing). It is not part of Material, so release it before
	// transferring the server signer to the caller.
	closeProductionSigner(caSigner)

	return materialFromSigners(caCert, serverCert, serverSigner), nil
}

// LoadServingMaterial loads only the TLS material required for HTTPS
// serving. Unlike ReloadMachine, it does NOT open the CA private key
// and does NOT attempt certificate renewal.
//
// It loads:
//   - CA certificate from disk (public DER only)
//   - server certificate from disk (public DER only)
//   - server private key via CNG (openProductionKey, read-only)
//
// It verifies:
//   - server cert ↔ server KSP public key match
//   - server cert was issued by the public CA
//   - server certificate SANs
//   - CA trust via read-only TrustVerifier (missing or conflicting trust fails closed)
//
// LoadServingMaterial never mutates LocalMachine\Root and never
// accesses the CA private key. It does not renew the server certificate; use
// ReloadMachine for the maintenance/renewal path. It is the function the HTTPS
// listener MUST use for normal runtime startup.
//
// If the caller cannot open the server key (e.g., running as a user
// without LocalService rights), it fails closed.
func LoadServingMaterial() (Material, error) {
	root, err := MachineAgentPath()
	if err != nil {
		return Material{}, fmt.Errorf("resolve machine agent path: %w", err)
	}
	tlsDir := filepath.Join(root, tlsSubDir)

	// Load CA certificate (public DER only — no CA key).
	caCertDER, err := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return Material{}, fmt.Errorf("read CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return Material{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Load server certificate from disk.
	serverCertDER, err := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return Material{}, fmt.Errorf("read server certificate: %w", err)
	}
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		return Material{}, fmt.Errorf("parse server certificate: %w", err)
	}

	// Open server key — the only private key needed for serving.
	// The server key is intended for the machine Agent Service /
	// LocalService principal. If the current process cannot open it,
	// fail closed — do not weaken key DACLs.
	serverSigner, err := openProductionKey(serverKeyName)
	if err != nil {
		return Material{}, fmt.Errorf("open server key: %w", err)
	}

	trustStore, err := PlatformTrustStore()
	if err != nil {
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("platform trust store: %w", err)
	}

	return loadServingMaterial(caCert, serverCert, serverSigner, trustStore)
}

// loadServingMaterial validates the serving material and returns the serving
// Material. It verifies the server cert/key match, that the server certificate
// was issued by the CA, the SANs, and (read-only) that the CA is trusted. The
// server signer is owned by the caller on success; on any failure it is released
// before returning. This is the testable core of LoadServingMaterial.
func loadServingMaterial(caCert, serverCert *x509.Certificate, serverSigner crypto.Signer, trustStore TrustVerifier) (Material, error) {
	// Verify server cert ↔ server key public key match.
	if err := verifyPublicKeyMatch(serverCert, serverSigner.Public()); err != nil {
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("server cert/key mismatch: %w", err)
	}

	// Verify server cert was issued by our CA (public check only).
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("server certificate was not issued by our CA: %w", err)
	}

	// Validate SANs.
	if err := validateSAN(serverCert); err != nil {
		closeProductionSigner(serverSigner)
		return Material{}, err
	}

	// Read-only trust verification. Missing or conflicting trust fails closed,
	// mirroring ReloadMachine's behavior.
	state, trustErr := trustStore.VerifyTrust(caCert.Raw)
	if trustErr != nil {
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("verify CA trust: %w", trustErr)
	}
	if state != TrustHealthy {
		closeProductionSigner(serverSigner)
		return Material{}, fmt.Errorf("CA not trusted: trust state is %s (elevated provisioning/repair required)", state)
	}

	return materialFromSigners(caCert, serverCert, serverSigner), nil
}

// closeProductionSigner closes a CNG signer if it implements the closer
// interface. It is best-effort: the CNG signer's Close never reports an error,
// so the returned error is discarded.
func closeProductionSigner(s crypto.Signer) {
	_ = closeSigner(s)
}

// checkInconsistentMachineState reports whether the production machine state is
// inconsistent (partial or incoherent) and must fail closed instead of being
// silently re-provisioned. It distinguishes a true first install (no certificate
// material and no persisted keys) and a complete state (both certificate DERs
// and both persisted keys) from every partial state.
//
// The key probe is open-only (open is openProductionKey in production), so the
// pre-check can never create a key. An unexpected open failure (permission,
// invalid/security-invalid persisted key, or other CNG error) is returned as an
// error so the caller fails closed, rather than being misclassified as "absent".
func checkInconsistentMachineState(root string, open func(string) (crypto.Signer, error)) (bool, error) {
	tlsDir := filepath.Join(root, tlsSubDir)
	caDER := fileExists(filepath.Join(tlsDir, caCertFile))
	serverDER := fileExists(filepath.Join(tlsDir, serverCertFile))

	// Partial certificate state: one DER present without the other. This is
	// already inconsistent; there is no need to probe the key store.
	if caDER != serverDER {
		return true, nil
	}

	// Probe both keys (open-only). Both must be present for a complete state,
	// and both absent for a true first install.
	caKey, err := probeKey(open, caKeyName)
	if err != nil {
		return false, err
	}
	serverKey, err := probeKey(open, serverKeyName)
	if err != nil {
		return false, err
	}

	return provisionStateInconsistent(caDER, serverDER, caKey, serverKey), nil
}

// probeKey probes a persisted production key using an open-only operation and
// reports whether it is present and openable. It distinguishes "absent"
// (ErrKeyNotFound — a clean signal for a true first install) from unexpected open
// failures (permission, invalid/security-invalid persisted key, or other CNG
// errors), which are returned so the caller fails closed. The open operation
// never creates a key.
func probeKey(open func(string) (crypto.Signer, error), name string) (bool, error) {
	signer, err := open(name)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	closeProductionSigner(signer)
	return true, nil
}
