package localtls

import (
	"crypto"
	"crypto/ecdsa"
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
	caKeyFile      = "ca-key.enc"
	serverCertFile = "server-cert.der"
	serverKeyFile  = "server-key.enc"
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
func ProvisionWithKeyStore(dataDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error) {
	return provisionWithKeyStore(dataDir, keyStore, trustStore, now, false)
}

// provisionWithKeyStore is the internal provisioning seam. repairTrust enables
// the elevated repair path: when a complete, internally valid persisted state
// has a missing (but otherwise exact) trust anchor, the same persisted CA is
// reinstalled rather than rejected. It must only be enabled for the elevated
// provisioning/repair operation; serving and reload-only paths remain read-only
// with respect to trust.
func provisionWithKeyStore(dataDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time, repairTrust bool) (Material, error) {
	if now == nil {
		now = time.Now
	}
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	if !fileExists(filepath.Join(tlsDir, caCertFile)) || !fileExists(filepath.Join(tlsDir, serverCertFile)) {
		return firstProvisionWithKeyStore(tlsDir, keyStore, trustStore, now)
	}
	return reloadWithKeyStore(tlsDir, keyStore, trustStore, now, repairTrust)
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

func reloadWithKeyStore(tlsDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time, repairTrust bool) (Material, error) {
	caCert, caSigner, err := loadCASigner(tlsDir, keyStore)
	if err != nil {
		return Material{}, fmt.Errorf("load CA: %w", err)
	}
	// The CA signer is a transient internal handle (used only for issuer and
	// renewal signing). It is never transferred to the caller.
	defer closeSigner(caSigner)

	serverCert, serverSigner, err := loadServerSigner(tlsDir, keyStore)
	if err != nil {
		return Material{}, fmt.Errorf("load server certificate: %w", err)
	}
	// The server signer is transferred to the caller on success.
	keepServerSigner := false
	defer func() {
		if !keepServerSigner {
			_ = closeSigner(serverSigner)
		}
	}()

	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		return Material{}, fmt.Errorf("server certificate was not issued by our CA: %w", err)
	}

	if err := validateSAN(serverCert); err != nil {
		return Material{}, err
	}

	state, trustErr := trustStore.VerifyTrust(caCert.Raw)
	if trustErr != nil {
		return Material{}, fmt.Errorf("verify CA trust: %w", trustErr)
	}
	switch state {
	case TrustHealthy:
		// Trust is present and exact: proceed.
	case TrustAbsent:
		if !repairTrust {
			return Material{}, fmt.Errorf("CA not trusted: trust state is %s (elevated provisioning/repair required)", state)
		}
		// Elevated repair: reinstall the exact persisted CA. This never
		// generates a new CA identity or replaces the persisted CA.
		if err := trustStore.InstallTrust(caCert.Raw); err != nil {
			return Material{}, fmt.Errorf("reinstall CA trust anchor: %w", err)
		}
		reinstalled, err := trustStore.VerifyTrust(caCert.Raw)
		if err != nil {
			return Material{}, fmt.Errorf("verify CA trust after reinstall: %w", err)
		}
		if reinstalled != TrustHealthy {
			return Material{}, fmt.Errorf("CA trust reinstall did not restore trust: trust state is %s", reinstalled)
		}
	default:
		// A conflicting or otherwise mismatching trust state is an explicit,
		// manual recovery condition and must never be overwritten.
		return Material{}, fmt.Errorf("CA not trusted: trust state is %s (elevated provisioning/repair required)", state)
	}

	needsRenewal := false
	nowTime := now()
	if nowTime.After(serverCert.NotAfter) || serverCert.NotAfter.Sub(nowTime) <= RenewalThreshold {
		needsRenewal = true
	}
	if needsRenewal {
		if err := validateCALifetime(caCert, nowTime); err != nil {
			return Material{}, err
		}
		// Reuse existing server signer so key rotation is decoupled from
		// certificate renewal. CNG persisted key is NOT overwritten.
		newServerCert, err := generateServerCertWithSigner(nowTime, caCert, caSigner, serverSigner)
		if err != nil {
			return Material{}, fmt.Errorf("renew server certificate: %w", err)
		}
		if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), newServerCert.Raw, 0600); err != nil {
			return Material{}, err
		}
		serverCert = newServerCert
	}

	keepServerSigner = true
	return materialFromSigners(caCert, serverCert, serverSigner), nil
}

func loadCASigner(tlsDir string, keyStore MachineKeyStore) (*x509.Certificate, crypto.Signer, error) {
	certDER, err := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	signer, err := keyStore.LoadOrCreateCAKey()
	if err != nil {
		return nil, nil, fmt.Errorf("load CA key: %w", err)
	}

	if err := verifyPublicKeyMatch(cert, signer.Public()); err != nil {
		_ = closeSigner(signer)
		return nil, nil, fmt.Errorf("CA cert/key mismatch: %w", err)
	}
	return cert, signer, nil
}

func loadServerSigner(tlsDir string, keyStore MachineKeyStore) (*x509.Certificate, crypto.Signer, error) {
	certDER, err := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server certificate: %w", err)
	}

	signer, err := keyStore.LoadOrCreateServerKey()
	if err != nil {
		return nil, nil, fmt.Errorf("load server key: %w", err)
	}

	if err := verifyPublicKeyMatch(cert, signer.Public()); err != nil {
		_ = closeSigner(signer)
		return nil, nil, fmt.Errorf("server cert/key mismatch: %w", err)
	}
	return cert, signer, nil
}

func marshaledKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return der, nil
}

// ----- legacy Protector-based provisioning (tests only) -----

// Provision provisions local TLS using a Protector. This is kept for
// backwards-compatible tests that use exported private keys.
func Provision(dataDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error) {
	if now == nil {
		now = time.Now
	}
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	allFiles := allFilesExist(tlsDir)
	if !allFiles {
		return firstProvision(tlsDir, protector, trustStore, now)
	}
	return reload(tlsDir, protector, trustStore, now)
}

func allFilesExist(tlsDir string) bool {
	for _, name := range []string{caCertFile, caKeyFile, serverCertFile, serverKeyFile} {
		if !fileExists(filepath.Join(tlsDir, name)) {
			return false
		}
	}
	return true
}

func firstProvision(tlsDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error) {
	if anyFileExists(tlsDir) {
		return Material{}, fmt.Errorf("incomplete local TLS material in %s; remove directory or restore all files", tlsDir)
	}
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return Material{}, fmt.Errorf("create tls directory: %w", err)
	}
	nowTime := now()
	caCert, caKey, err := generateCA(nowTime)
	if err != nil {
		return Material{}, fmt.Errorf("generate CA: %w", err)
	}
	serverCert, serverKey, err := generateServerCert(nowTime, caCert, caKey)
	if err != nil {
		return Material{}, fmt.Errorf("generate server certificate: %w", err)
	}
	caKeyDER, err := marshaledKey(caKey)
	if err != nil {
		return Material{}, fmt.Errorf("marshal CA key: %w", err)
	}
	caKeyProtected, err := protector.Protect(caKeyDER)
	if err != nil {
		return Material{}, fmt.Errorf("protect CA key: %w", err)
	}
	serverKeyDER, err := marshaledKey(serverKey)
	if err != nil {
		return Material{}, fmt.Errorf("marshal server key: %w", err)
	}
	serverKeyProtected, err := protector.Protect(serverKeyDER)
	if err != nil {
		return Material{}, fmt.Errorf("protect server key: %w", err)
	}
	if err := atomicWrite(filepath.Join(tlsDir, caCertFile), caCert.Raw, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, "ca-key.enc"), caKeyProtected, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), serverCert.Raw, 0600); err != nil {
		return Material{}, err
	}
	if err := atomicWrite(filepath.Join(tlsDir, "server-key.enc"), serverKeyProtected, 0600); err != nil {
		return Material{}, err
	}
	if err := trustStore.InstallTrust(caCert.Raw); err != nil {
		return Material{}, fmt.Errorf("install CA in trust store: %w", err)
	}
	return materialFrom(caCert, caKey, serverCert, serverKey), nil
}

func reload(tlsDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error) {
	caCert, caKey, err := loadCA(tlsDir, protector)
	if err != nil {
		return Material{}, fmt.Errorf("load CA: %w", err)
	}
	serverCert, serverKey, err := loadServer(tlsDir, protector)
	if err != nil {
		return Material{}, fmt.Errorf("load server certificate: %w", err)
	}
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		return Material{}, fmt.Errorf("server certificate was not issued by our CA: %w", err)
	}
	if err := validateSAN(serverCert); err != nil {
		return Material{}, err
	}
	state, trustErr := trustStore.VerifyTrust(caCert.Raw)
	if trustErr != nil {
		return Material{}, fmt.Errorf("verify CA trust: %w", trustErr)
	}
	if state != TrustHealthy {
		return Material{}, fmt.Errorf("CA not trusted: trust state is %s (elevated provisioning/repair required)", state)
	}
	needsRenewal := false
	nowTime := now()
	if nowTime.After(serverCert.NotAfter) || serverCert.NotAfter.Sub(nowTime) <= RenewalThreshold {
		needsRenewal = true
	}
	if needsRenewal {
		if err := validateCALifetime(caCert, nowTime); err != nil {
			return Material{}, err
		}
		newServerCert, newServerKey, err := generateServerCert(nowTime, caCert, caKey)
		if err != nil {
			return Material{}, fmt.Errorf("renew server certificate: %w", err)
		}
		serverKeyDER, err := marshaledKey(newServerKey)
		if err != nil {
			return Material{}, fmt.Errorf("marshal renewed server key: %w", err)
		}
		serverKeyProtected, err := protector.Protect(serverKeyDER)
		if err != nil {
			return Material{}, fmt.Errorf("protect renewed server key: %w", err)
		}
		if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), newServerCert.Raw, 0600); err != nil {
			return Material{}, err
		}
		if err := atomicWrite(filepath.Join(tlsDir, "server-key.enc"), serverKeyProtected, 0600); err != nil {
			return Material{}, err
		}
		serverCert = newServerCert
		serverKey = newServerKey
	}
	return materialFrom(caCert, caKey, serverCert, serverKey), nil
}

func loadCA(tlsDir string, protector Protector) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	protected, err := os.ReadFile(filepath.Join(tlsDir, "ca-key.enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("read protected CA key: %w", err)
	}
	keyDER, err := protector.Unprotect(protected)
	if err != nil {
		return nil, nil, fmt.Errorf("unprotect CA key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected key type %T", key)
	}
	if err := verifyKeyMatch(cert, ecKey); err != nil {
		return nil, nil, fmt.Errorf("CA cert/key mismatch: %w", err)
	}
	return cert, ecKey, nil
}

func loadServer(tlsDir string, protector Protector) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server certificate: %w", err)
	}
	protected, err := os.ReadFile(filepath.Join(tlsDir, "server-key.enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("read protected server key: %w", err)
	}
	keyDER, err := protector.Unprotect(protected)
	if err != nil {
		return nil, nil, fmt.Errorf("unprotect server key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected key type %T", key)
	}
	if err := verifyKeyMatch(cert, ecKey); err != nil {
		return nil, nil, fmt.Errorf("server cert/key mismatch: %w", err)
	}
	return cert, ecKey, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func anyFileExists(tlsDir string) bool {
	for _, name := range []string{caCertFile, caKeyFile, serverCertFile, serverKeyFile} {
		if fileExists(filepath.Join(tlsDir, name)) {
			return true
		}
	}
	return false
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

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

func materialFrom(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serverCert *x509.Certificate, serverKey *ecdsa.PrivateKey) Material {
	return Material{
		Certificate:         tlsCertFromMaterial(serverCert, serverKey),
		CACertificate:       caCert,
		ServerCertificate:   serverCert,
		CAFingerprintSHA256: sha256.Sum256(caCert.Raw),
	}
}

func materialFromSigners(caCert, serverCert *x509.Certificate, serverSigner crypto.Signer) Material {
	return Material{
		Certificate:         tlsCertFromSigner(serverCert, serverSigner),
		CACertificate:       caCert,
		ServerCertificate:   serverCert,
		CAFingerprintSHA256: sha256.Sum256(caCert.Raw),
	}
}
