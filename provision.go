package localtls

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
// idempotent in effect: the first Close of the underlying CNG signer may report
// a failure to release a native handle, which is returned and never retried;
// repeated calls are harmless and return nil. After Close, the serving
// certificate must not be used for new TLS handshakes.
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
// Existing-state keys are opened through keyStore, never created.
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

// ErrRollbackIncomplete indicates that a first install failed and could not
// undo everything it had created: a key it created may still persist, or a
// certificate DER it wrote may still be on disk. The error also carries the
// primary failure and, for each artifact left behind, the reason (for example
// ErrKeyDeletionNotCompletable, ErrKeyNotFound or ErrDeleteVerificationFailed)
// and the SHA-256 of the key's SubjectPublicKeyInfo when it is known, for an
// authorized administrative recovery.
var ErrRollbackIncomplete = errors.New("first install rollback incomplete")

// ErrKeyReleaseUnconfirmed indicates that closing a key handle opened or
// created by a first install reported an error: the release of that native
// handle is not confirmed. It is never retried. It says nothing about whether
// the persisted key exists; that is reported separately (for example by
// ErrRollbackIncomplete).
var ErrKeyReleaseUnconfirmed = errors.New("key handle release not confirmed")

// releaseSigner closes one handle of the first install exactly once and
// reports a failure as ErrKeyReleaseUnconfirmed with the key role.
func releaseSigner(role string, s crypto.Signer) error {
	if err := closeSigner(s); err != nil {
		return fmt.Errorf("release the %s key handle: %w: %w", role, ErrKeyReleaseUnconfirmed, err)
	}
	return nil
}

// firstInstall records what one first install created, so that a failure
// before both certificate DERs are persisted is compensated exactly: only the
// keys this call created, identified by the SubjectPublicKeyInfo recorded right
// after each Create, and only the DERs this call attempted to write (neither
// existed before a first install). Nothing is ever deleted
// by name alone, and a key is never reopened to learn its identity.
type firstInstall struct {
	keys MachineKeyDeleter

	caCreated, serverCreated bool
	caSPKI, serverSPKI       []byte // nil when the created key's SPKI could not be encoded
	written                  []string
}

// recordSPKI encodes the SubjectPublicKeyInfo of a key this call just created.
func recordSPKI(signer crypto.Signer) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("encode the public key of the created key: %w", err)
	}
	return spki, nil
}

// rollback undoes the artifacts of a failed first install. The signers must be
// closed before it runs. It removes the DERs this call wrote, newest first,
// then deletes the server key and the CA key this call created, each through
// its recorded SubjectPublicKeyInfo. Every step is attempted; it returns nil
// only when everything was undone, otherwise an error wrapping
// ErrRollbackIncomplete.
func (fi *firstInstall) rollback() error {
	var errs []error
	for i := len(fi.written) - 1; i >= 0; i-- {
		if err := os.Remove(fi.written[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s written by this install: %w", fi.written[i], err))
		}
	}
	if fi.serverCreated {
		if err := deleteCreatedKey("server", fi.serverSPKI, fi.keys.DeleteServerKey); err != nil {
			errs = append(errs, err)
		}
	}
	if fi.caCreated {
		if err := deleteCreatedKey("CA", fi.caSPKI, fi.keys.DeleteCAKey); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrRollbackIncomplete, errors.Join(errs...))
}

// deleteCreatedKey deletes one key created by the failed install through its
// recorded SubjectPublicKeyInfo. Without it the key is left in place and
// reported as ErrKeyDeletionNotCompletable.
func deleteCreatedKey(role string, spki []byte, del func([]byte) error) error {
	if spki == nil {
		return fmt.Errorf("%s key created by this install: %w: its public key could not be encoded; the key may persist", role, ErrKeyDeletionNotCompletable)
	}
	if err := del(spki); err != nil {
		return fmt.Errorf("delete %s key created by this install (SPKI SHA-256 %x): %w", role, sha256.Sum256(spki), err)
	}
	return nil
}

// firstProvisionWithKeyStore performs the first install: it creates both keys
// (never opening or adopting an existing one), issues the CA and server
// certificates, persists both DERs and installs the CA trust anchor.
//
// Until both DERs are persisted a failure is compensated (see
// firstInstall.rollback): the error carries the primary cause, any handle
// whose release failed (ErrKeyReleaseUnconfirmed) and, when the compensation
// is incomplete, ErrRollbackIncomplete. A create that fails
// leaves nothing this call owns: windowscng deletes the key of its own failed
// create, or reports windowscng.ErrCleanupFailed when it could not, and that
// key is not deleted again. After both DERs are persisted nothing is
// compensated: a CA handle whose release is not confirmed
// (ErrKeyReleaseUnconfirmed) stops the install before the trust anchor is
// installed, and a failure to install the trust anchor is returned as is. The
// keys and DERs then stay, a later ProvisionMachine fails closed with
// ErrTrustNotHealthy, and CleanupMachine removes them with verified deletes.
func firstProvisionWithKeyStore(tlsDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error) {
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return Material{}, fmt.Errorf("create tls directory: %w", err)
	}

	nowTime := now()
	fi := &firstInstall{keys: keyStore}
	var caSigner, serverSigner crypto.Signer
	fail := func(err error) (Material, error) {
		// Release every handle before deleting the keys they were opened on.
		// A failed release is reported, not retried; the rollback still deletes
		// the keys this call created, each through its recorded identity, on a
		// handle of its own.
		errs := []error{err}
		if serverSigner != nil {
			errs = append(errs, releaseSigner("server", serverSigner))
		}
		if caSigner != nil {
			errs = append(errs, releaseSigner("CA", caSigner))
		}
		errs = append(errs, fi.rollback())
		return Material{}, errors.Join(errs...)
	}

	signer, err := keyStore.CreateCAKey()
	if err != nil {
		return Material{}, fmt.Errorf("create CA key: %w", err)
	}
	caSigner, fi.caCreated = signer, true
	if fi.caSPKI, err = recordSPKI(caSigner); err != nil {
		return fail(fmt.Errorf("record CA key identity: %w", err))
	}

	caCert, err := generateCAWithSigner(nowTime, caSigner)
	if err != nil {
		return fail(fmt.Errorf("generate CA certificate: %w", err))
	}

	signer, err = keyStore.CreateServerKey()
	if err != nil {
		return fail(fmt.Errorf("create server key: %w", err))
	}
	serverSigner, fi.serverCreated = signer, true
	if fi.serverSPKI, err = recordSPKI(serverSigner); err != nil {
		return fail(fmt.Errorf("record server key identity: %w", err))
	}

	serverCert, err := generateServerCertWithSigner(nowTime, caCert, caSigner, serverSigner)
	if err != nil {
		return fail(fmt.Errorf("generate server certificate: %w", err))
	}
	// Bootstrap hardening: the generated pair must pass the common validator
	// before anything is persisted or trusted.
	if err := validateServerLeaf(serverCert, caCert, serverSigner.Public(), nowTime); err != nil {
		return fail(fmt.Errorf("validate generated server certificate: %w", err))
	}

	// Each DER is recorded before it is written: a replace that reports an
	// error may already have taken effect, and on a first install neither DER
	// existed before, so the rollback removes whatever this call left.
	for _, der := range []struct {
		name string
		raw  []byte
	}{{caCertFile, caCert.Raw}, {serverCertFile, serverCert.Raw}} {
		path := filepath.Join(tlsDir, der.name)
		fi.written = append(fi.written, path)
		if err := atomicWrite(path, der.raw, 0600); err != nil {
			return fail(err)
		}
	}

	// Both DERs are persisted: they are now the durable record of both key
	// identities, and nothing below is compensated. The CA signer is a
	// transient handle; the server signer is transferred on success. A CA
	// handle whose release is not confirmed stops the install before the
	// trust anchor is installed.
	const notRolledBack = "the keys and certificates are persisted and are not rolled back; run CleanupMachine before a new first install"
	if err := releaseSigner("CA", caSigner); err != nil {
		return Material{}, errors.Join(fmt.Errorf("%w (%s)", err, notRolledBack), releaseSigner("server", serverSigner))
	}
	if err := trustStore.InstallTrust(caCert.Raw); err != nil {
		return Material{}, errors.Join(fmt.Errorf("install CA in trust store: %w (%s)", err, notRolledBack), releaseSigner("server", serverSigner))
	}

	return materialFromSigners(caCert, serverCert, serverSigner), nil
}

// reloadWithKeyStore verifies existing state through keyStore. It shares
// reloadExisting with ReloadMachine (verifyExistingState policy) and never
// renews or writes DER. It opens the existing keys only and never creates one.
func reloadWithKeyStore(tlsDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error) {
	return reloadExisting(machineEnv{
		tlsDir:        tlsDir,
		openCAKey:     keyStore.OpenCAKey,
		openServerKey: keyStore.OpenServerKey,
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
