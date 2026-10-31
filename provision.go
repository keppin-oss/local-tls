package localtls

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

const tlsSubDir = "tls"

const (
	caCertFile     = "ca-cert.der"
	serverCertFile = "server-cert.der"
)

// Material contains the provisioned local TLS material.
type Material struct {
	Certificate         tls.Certificate
	CACertificate       *x509.Certificate
	ServerCertificate   *x509.Certificate
	CAFingerprintSHA256 [32]byte
}

// Close releases the process-local native CNG handle backing the serving
// signer. It never deletes the persisted CNG key, never removes certificates or
// trust anchors, and never triggers CleanupMachine or CleanupMachineBySHA256.
// Lifecycle release is distinct from persisted-key deletion and from Local TLS
// uninstall/cleanup.
//
// Close is safe to call after a successful production machine operation. It is
// idempotent in effect: the underlying CNG signer's Close is safe to call
// repeatedly and reports no error. After Close, the serving certificate must
// not be used for new TLS handshakes.
//
// Material is single-owner: do not copy it by value and then reuse the copy
// after Close, since both copies reference the same underlying signer.
func (m *Material) Close() error {
	if m == nil {
		return nil
	}
	if s, ok := m.Certificate.PrivateKey.(crypto.Signer); ok {
		return closeSigner(s)
	}
	return nil
}

// closeSigner releases the process-local native handle backing a crypto.Signer
// when it implements interface{ Close() error }. A signer without that method
// (for example the in-memory *ecdsa.PrivateKey used on the legacy/test path)
// has no native handle and is a no-op. It never deletes a persisted key.
func closeSigner(s crypto.Signer) error {
	if c, ok := s.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// provisionStateInconsistent reports whether the given production material
// presence describes an inconsistent partial state that must fail closed rather
// than be silently re-provisioned (which would regenerate the CA identity or
// create replacement keys).
//
// A true first install has no certificate DER, no persisted CA key, and no
// persisted server key. A complete state has both certificate DERs and both
// persisted keys. Everything else — one certificate without the other, a
// persisted key without its certificate, or certificate material without its
// persisted keys — is inconsistent.
func provisionStateInconsistent(caDER, serverDER, caKey, serverKey bool) bool {
	if caDER != serverDER {
		// One certificate present without the other.
		return true
	}
	if !caDER {
		// No certificate material: a true first install requires no persisted keys.
		return caKey || serverKey
	}
	// Both certificates present: a complete state requires both persisted keys.
	return !(caKey && serverKey)
}

// ProvisionWithKeyStore provisions local TLS using a MachineKeyStore for
// persistent signing keys. Only public certificate DERs are written to disk;
// private keys remain in the machine-scoped key store.
//
// First install is entered only when both the CA and the server certificate
// DER are absent. A DER whose presence cannot be determined (any stat error
// other than not-exist), or exactly one present DER, fails closed with
// ErrInconsistentMachineState: the CA certificate is never reissued for an
// existing state. ProvisionWithKeyStore performs no CA-key pre-check;
// ProvisionMachine adds the conservative pre-check and documents the
// single-writer caller contract that also applies here.
//
// On existing state it verifies the persisted material with the common
// validator and never writes DER, renews or stages. A valid leaf is returned
// with a nil error even within RenewalThreshold of expiry: success means the
// existing state was verified, not that a renewal occurred (renewal goes
// through StageServerRenewal and the consumer confirmation flow). An expired
// leaf fails with ErrRenewalDue and ErrCertificateNotValidNow; any other
// validation or trust failure returns a zero Material with a classified error.
// Existing-state keys are acquired through keyStore (open-or-create).
func ProvisionWithKeyStore(dataDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error) {
	if now == nil {
		now = time.Now
	}
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	caExists, err := osFS.statExists(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return Material{}, fmt.Errorf("%w: cannot determine whether the CA certificate exists: %v", ErrInconsistentMachineState, err)
	}
	serverExists, err := osFS.statExists(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return Material{}, fmt.Errorf("%w: cannot determine whether the server certificate exists: %v", ErrInconsistentMachineState, err)
	}
	switch {
	case !caExists && !serverExists:
		return firstProvisionWithKeyStore(tlsDir, keyStore, trustStore, now)
	case caExists && !serverExists:
		return Material{}, fmt.Errorf(
			"%w: the CA certificate exists but the server certificate is missing in %s — "+
				"automatic CA reissue is forbidden to prevent duplicate trust anchors; "+
				"restore the server certificate or perform a full re-provisioning cleanup",
			ErrInconsistentMachineState, tlsDir)
	case !caExists && serverExists:
		return Material{}, fmt.Errorf(
			"%w: the server certificate exists but the CA certificate is missing in %s — "+
				"automatic CA regeneration is forbidden to prevent duplicate trust anchors; "+
				"restore the certificate material or perform a full re-provisioning cleanup",
			ErrInconsistentMachineState, tlsDir)
	}
	return reloadWithKeyStore(tlsDir, keyStore, trustStore, now)
}

func firstProvisionWithKeyStore(tlsDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error) {
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return Material{}, fmt.Errorf("create tls directory: %w", err)
	}

	nowTime := now()

	caSigner, err := keyStore.LoadOrCreateCAKey()
	if err != nil {
		return Material{}, fmt.Errorf("load or create CA key: %w", err)
	}
	// The CA signer is a transient internal handle used only to sign the server
	// certificate. It is never transferred to the caller, so release it on every
	// exit path (success and error).
	defer closeSigner(caSigner)

	caCert, err := generateCAWithSigner(nowTime, caSigner)
	if err != nil {
		return Material{}, fmt.Errorf("generate CA certificate: %w", err)
	}

	serverSigner, err := keyStore.LoadOrCreateServerKey()
	if err != nil {
		return Material{}, fmt.Errorf("load or create server key: %w", err)
	}
	// The server signer is transferred to the caller on success; release it only
	// when construction fails part-way through.
	keepServerSigner := false
	defer func() {
		if !keepServerSigner {
			_ = closeSigner(serverSigner)
		}
	}()

	serverCert, err := generateServerCertWithSigner(nowTime, caCert, caSigner, serverSigner)
	if err != nil {
		return Material{}, fmt.Errorf("generate server certificate: %w", err)
	}
	// Bootstrap hardening: the generated pair must pass the common validator
	// before anything is persisted or trusted.
	if err := validateServerLeaf(serverCert, caCert, serverSigner.Public(), nowTime); err != nil {
		return Material{}, fmt.Errorf("validate generated server certificate: %w", err)
	}

	if err := atomicWrite(filepath.Join(tlsDir, caCertFile), caCert.Raw, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), serverCert.Raw, 0600); err != nil {
		return Material{}, err
	}

	if err := trustStore.InstallTrust(caCert.Raw); err != nil {
		return Material{}, fmt.Errorf("install CA in trust store: %w", err)
	}

	keepServerSigner = true
	return materialFromSigners(caCert, serverCert, serverSigner), nil
}

// reloadWithKeyStore verifies existing state through keyStore. It shares
// reloadExisting with ReloadMachine (verifyExistingState policy) and never
// renews or writes DER. Keys are acquired through MachineKeyStore, whose only
// operations are open-or-create (documented in the README); the
// renewal and runtime paths open existing keys only.
func reloadWithKeyStore(tlsDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error) {
	return reloadExisting(machineEnv{
		tlsDir:        tlsDir,
		openCAKey:     keyStore.LoadOrCreateCAKey,
		openServerKey: keyStore.LoadOrCreateServerKey,
		trust:         trustStore,
		now:           now,
		fs:            osFS,
	}, verifyExistingState)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func validateSAN(cert *x509.Certificate) error {
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "localhost" {
		return fmt.Errorf("server certificate DNS SAN must be exactly [localhost]")
	}
	if len(cert.IPAddresses) != 2 {
		return fmt.Errorf("server certificate IP SAN must have exactly 2 entries")
	}
	found4 := false
	found6 := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			found4 = true
		}
		if ip.Equal(net.IPv6loopback) {
			found6 = true
		}
	}
	if !found4 || !found6 {
		return fmt.Errorf("server certificate IP SAN must contain 127.0.0.1 and ::1")
	}
	return nil
}

func materialFromSigners(caCert, serverCert *x509.Certificate, serverSigner crypto.Signer) Material {
	return Material{
		Certificate:         tlsCertFromSigner(serverCert, serverSigner),
		CACertificate:       caCert,
		ServerCertificate:   serverCert,
		CAFingerprintSHA256: sha256.Sum256(caCert.Raw),
	}
}
