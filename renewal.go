package localtls

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

const (
	pendingServerCertFile = "server-cert.pending.der"
	prevServerCertFile    = "server-cert.prev.der"
)

var (
	// ErrRenewalDue indicates that the persisted server certificate is due for
	// renewal. Neither ReloadMachine nor existing-state provisioning renews
	// implicitly; the caller stages a renewal with StageServerRenewal.
	// ReloadMachine reports it whenever the leaf is within RenewalThreshold of
	// expiry; existing-state provisioning reports it only once the leaf has
	// expired (a still-valid leaf in the renewal window is returned with a nil
	// error). An expired leaf also matches ErrCertificateNotValidNow. CA, key,
	// certificate identity and trust failures detected first are reported with
	// their own errors and do not match ErrRenewalDue.
	ErrRenewalDue = errors.New("server certificate renewal is due; stage it with StageServerRenewal")

	// ErrNoCandidate indicates that a CandidateRef does not describe a staged
	// candidate (its Outcome is not RenewalCandidateStaged).
	ErrNoCandidate = errors.New("candidate reference does not describe a staged candidate")

	// ErrCandidateNotFound indicates that no pending candidate DER exists.
	ErrCandidateNotFound = errors.New("pending server certificate candidate not found")

	// ErrCandidateMismatch indicates that the persisted pending candidate is
	// not the one identified by the CandidateRef. Nothing is changed.
	ErrCandidateMismatch = errors.New("pending server certificate candidate does not match the candidate reference")

	// ErrCandidateStale indicates that the persisted server certificate or CA
	// certificate is no longer the base the candidate was staged against.
	// Nothing is changed; stage again.
	ErrCandidateStale = errors.New("candidate reference is stale: persisted server or CA certificate changed since staging")

	// ErrCandidatePromoted indicates that the candidate has already been
	// promoted to the persisted server certificate, so it can no longer be
	// abandoned. Abandon never reverses a completed promotion.
	ErrCandidatePromoted = errors.New("candidate has already been promoted")

	// ErrPromotionUnconfirmed indicates that the final promotion step reported
	// an error whose effect is not known: the candidate may or may not have
	// become the persisted server certificate. Retry ConfirmServingCandidate
	// with the same CandidateRef to reconcile; never treat this as "not
	// promoted".
	ErrPromotionUnconfirmed = errors.New("server certificate promotion outcome unconfirmed")
)

// RenewalOutcome is the result of StageServerRenewal. The zero value is not a
// valid outcome.
type RenewalOutcome int

const (
	// RenewalNotDue means the persisted server certificate is not within
	// RenewalThreshold of expiry; no candidate was staged.
	RenewalNotDue RenewalOutcome = iota + 1

	// RenewalCandidateStaged means a validated candidate is persisted as the
	// pending server certificate. The persisted server certificate is
	// unchanged.
	RenewalCandidateStaged
)

// String returns a human-readable representation of the outcome.
func (o RenewalOutcome) String() string {
	switch o {
	case RenewalNotDue:
		return "not-due"
	case RenewalCandidateStaged:
		return "candidate-staged"
	default:
		return fmt.Sprintf("unknown(%d)", int(o))
	}
}

// CandidateRef identifies one staged renewal attempt by public digests. It is
// returned by StageServerRenewal and passed back unchanged to
// LoadServingCandidate, ConfirmServingCandidate and AbandonServingCandidate.
//
// CandidateRef is public metadata only. It is not a secret, not an
// authorization, not a compare-and-swap token, and not proof that any listener
// activated the candidate. The caller keeps it for the whole attempt; if it is
// lost, the attempt is restarted (stage, load, activate, attest, confirm), and
// the presence of a pending file is never treated as confirmation.
type CandidateRef struct {
	// Outcome reports whether a candidate was staged.
	Outcome RenewalOutcome
	// CandidateSHA256 is the SHA-256 of the pending candidate DER. Zero when
	// Outcome is RenewalNotDue.
	CandidateSHA256 [32]byte
	// BaseSHA256 is the SHA-256 of the persisted server certificate DER the
	// candidate was staged against.
	BaseSHA256 [32]byte
	// CASHA256 is the SHA-256 of the CA certificate DER.
	CASHA256 [32]byte
}

// machineEnv bundles the dependencies of the platform-independent load,
// reload and renewal logic. Key openers must open existing keys only; they
// never create a key.
type machineEnv struct {
	tlsDir        string
	openCAKey     func() (crypto.Signer, error)
	openServerKey func() (crypto.Signer, error)
	trust         TrustVerifier
	now           func() time.Time
	fs            fileSystem
}

func (e machineEnv) path(name string) string { return filepath.Join(e.tlsDir, name) }

func (e machineEnv) readCert(name, what string) ([]byte, *x509.Certificate, error) {
	der, err := e.fs.readFile(e.path(name))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s certificate: %w", what, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s certificate: %w", what, err)
	}
	return der, cert, nil
}

// readPersistedServer reads the persisted server certificate; a missing file
// is reported as inconsistent state rather than as a reason to regenerate.
func (e machineEnv) readPersistedServer() ([]byte, *x509.Certificate, error) {
	der, cert, err := e.readCert(serverCertFile, "server")
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: %v", ErrInconsistentMachineState, err)
	}
	return der, cert, err
}

// loadServing is the platform-independent body of LoadServingMaterial. It
// reads only the persisted server certificate, opens only the server key,
// never mutates state and fails closed on any validation or trust failure,
// including an expired certificate.
func loadServing(e machineEnv) (Material, error) {
	caDER, caCert, err := e.readCert(caCertFile, "CA")
	if err != nil {
		return Material{}, err
	}
	_, serverCert, err := e.readCert(serverCertFile, "server")
	if err != nil {
		return Material{}, err
	}
	return loadValidatedServing(e, caDER, caCert, serverCert)
}

// loadValidatedServing opens the server key and returns Material for leaf
// only if the leaf passes validateServerLeaf and the CA trust is healthy. The
// server signer is transferred to the caller on success and closed otherwise.
func loadValidatedServing(e machineEnv, caDER []byte, caCert, leaf *x509.Certificate) (Material, error) {
	serverSigner, err := e.openServerKey()
	if err != nil {
		return Material{}, fmt.Errorf("open server key: %w", err)
	}
	if err := validateServerLeaf(leaf, caCert, serverSigner.Public(), e.now()); err != nil {
		closeSigner(serverSigner)
		return Material{}, err
	}
	if err := requireTrustHealthy(e.trust, caDER); err != nil {
		closeSigner(serverSigner)
		return Material{}, err
	}
	return materialFromSigners(caCert, leaf, serverSigner), nil
}

// reloadPolicy selects how reloadExisting treats a leaf that is still valid
// but within RenewalThreshold of expiry.
type reloadPolicy int

const (
	// reportRenewalDue (ReloadMachine) fails with ErrRenewalDue whenever
	// renewal is due, even while the leaf is still valid.
	reportRenewalDue reloadPolicy = iota + 1

	// verifyExistingState (existing-state provisioning) returns the fully
	// validated Material with a nil error while the leaf is valid, including
	// during the renewal window. Success means "existing state verified", not
	// "renewed".
	verifyExistingState
)

// reloadExisting is the shared body of ReloadMachine (open-only key access,
// reportRenewalDue) and the existing-state ProvisionWithKeyStore path
// (MachineKeyStore access, verifyExistingState). It verifies the complete
// persisted state with the common validator and never writes or renews. An
// expired leaf always fails with ErrRenewalDue joined with
// ErrCertificateNotValidNow. On any error both signers are released and a zero
// Material is returned; a live handle is never returned with an error.
func reloadExisting(e machineEnv, policy reloadPolicy) (Material, error) {
	caDER, caCert, err := e.readCert(caCertFile, "CA")
	if err != nil {
		return Material{}, fmt.Errorf("load CA: %w", err)
	}
	caSigner, err := e.openCAKey()
	if err != nil {
		return Material{}, fmt.Errorf("load CA: open CA key: %w", err)
	}
	// The CA signer is used only to verify the CA key match; it is never
	// transferred to the caller.
	defer closeSigner(caSigner)
	if err := verifyPublicKeyMatch(caCert, caSigner.Public()); err != nil {
		return Material{}, fmt.Errorf("load CA: CA cert/key mismatch: %w", err)
	}

	_, serverCert, err := e.readCert(serverCertFile, "server")
	if err != nil {
		return Material{}, fmt.Errorf("load server certificate: %w", err)
	}
	serverSigner, err := e.openServerKey()
	if err != nil {
		return Material{}, fmt.Errorf("load server certificate: open server key: %w", err)
	}
	keepServerSigner := false
	defer func() {
		if !keepServerSigner {
			closeSigner(serverSigner)
		}
	}()

	now := e.now()
	if err := validateCA(caCert, now); err != nil {
		return Material{}, err
	}
	if err := validateServerIdentity(serverCert, caCert, serverSigner.Public()); err != nil {
		return Material{}, err
	}
	if err := requireTrustHealthy(e.trust, caDER); err != nil {
		return Material{}, err
	}
	if renewalDue(serverCert, now) {
		if now.After(serverCert.NotAfter) {
			return Material{}, fmt.Errorf("%w: %w: server certificate expired at %s", ErrRenewalDue, ErrCertificateNotValidNow,
				serverCert.NotAfter.UTC().Format(time.RFC3339))
		}
		if policy != verifyExistingState {
			return Material{}, fmt.Errorf("%w: server certificate expires at %s", ErrRenewalDue,
				serverCert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if err := validateServerLeaf(serverCert, caCert, serverSigner.Public(), now); err != nil {
		return Material{}, err
	}

	keepServerSigner = true
	return materialFromSigners(caCert, serverCert, serverSigner), nil
}

// usefulCandidate reports whether cand actually advances the persisted
// server certificate: different bytes, a later expiry, and not itself due for
// renewal.
func usefulCandidate(cand, cur *x509.Certificate, now time.Time) bool {
	return !bytes.Equal(cand.Raw, cur.Raw) && cand.NotAfter.After(cur.NotAfter) && !renewalDue(cand, now)
}

// stageServerRenewal is the platform-independent body of StageServerRenewal.
func stageServerRenewal(e machineEnv) (CandidateRef, error) {
	now := e.now()

	caDER, caCert, err := e.readCert(caCertFile, "CA")
	if err != nil {
		return CandidateRef{}, err
	}
	if err := validateCA(caCert, now); err != nil {
		return CandidateRef{}, err
	}
	if err := requireTrustHealthy(e.trust, caDER); err != nil {
		return CandidateRef{}, err
	}
	curDER, curCert, err := e.readPersistedServer()
	if err != nil {
		return CandidateRef{}, err
	}

	caSigner, err := e.openCAKey()
	if err != nil {
		return CandidateRef{}, fmt.Errorf("open CA key: %w", err)
	}
	defer closeSigner(caSigner)
	if err := verifyPublicKeyMatch(caCert, caSigner.Public()); err != nil {
		return CandidateRef{}, fmt.Errorf("CA cert/key mismatch: %w", err)
	}
	serverSigner, err := e.openServerKey()
	if err != nil {
		return CandidateRef{}, fmt.Errorf("open server key: %w", err)
	}
	defer closeSigner(serverSigner)

	// The previous leaf may already be expired: only its identity is
	// required here. Serving eligibility is a separate check.
	if err := validateServerIdentity(curCert, caCert, serverSigner.Public()); err != nil {
		return CandidateRef{}, err
	}

	ref := CandidateRef{
		Outcome:    RenewalNotDue,
		BaseSHA256: sha256.Sum256(curDER),
		CASHA256:   sha256.Sum256(caDER),
	}
	if !renewalDue(curCert, now) {
		return ref, nil
	}

	if err := e.fs.removeOrphanTemps(e.tlsDir); err != nil {
		return CandidateRef{}, err
	}

	pendingPath := e.path(pendingServerCertFile)
	pendDER, err := e.fs.readFile(pendingPath)
	switch {
	case err == nil:
		// Reuse an existing pending candidate only when it is valid now
		// and actually advances the persisted certificate. Anything else is
		// stale and is replaced below.
		if pend, perr := x509.ParseCertificate(pendDER); perr == nil &&
			validateServerLeaf(pend, caCert, serverSigner.Public(), now) == nil &&
			usefulCandidate(pend, curCert, now) {
			ref.Outcome = RenewalCandidateStaged
			ref.CandidateSHA256 = sha256.Sum256(pendDER)
			return ref, nil
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return CandidateRef{}, fmt.Errorf("read pending server certificate: %w", err)
	}

	if now.Add(serverValidity).After(caCert.NotAfter) {
		return CandidateRef{}, fmt.Errorf("%w: a %s renewal would end after the CA expires at %s; CA renewal is not automatic",
			ErrLeafOutlivesCA, serverValidity, caCert.NotAfter.UTC().Format(time.RFC3339))
	}
	cand, err := generateServerCertWithSigner(now, caCert, caSigner, serverSigner)
	if err != nil {
		return CandidateRef{}, fmt.Errorf("generate server certificate candidate: %w", err)
	}
	if err := validateServerLeaf(cand, caCert, serverSigner.Public(), now); err != nil {
		return CandidateRef{}, fmt.Errorf("validate server certificate candidate: %w", err)
	}
	if !usefulCandidate(cand, curCert, now) {
		return CandidateRef{}, fmt.Errorf("server certificate candidate does not advance the persisted certificate")
	}
	if err := e.fs.atomicWrite(pendingPath, cand.Raw, 0600); err != nil {
		return CandidateRef{}, fmt.Errorf("persist pending server certificate: %w", err)
	}
	// The re-read detects a write that did not land as intended. It is not
	// evidence of physical durability.
	back, err := e.fs.readFile(pendingPath)
	if err != nil {
		return CandidateRef{}, fmt.Errorf("re-read pending server certificate: %w", err)
	}
	if !bytes.Equal(back, cand.Raw) {
		return CandidateRef{}, fmt.Errorf("re-read pending server certificate: content differs from the written candidate")
	}

	ref.Outcome = RenewalCandidateStaged
	ref.CandidateSHA256 = sha256.Sum256(cand.Raw)
	return ref, nil
}

// checkStagedRef rejects references that do not describe a staged candidate.
func checkStagedRef(ref CandidateRef) error {
	if ref.Outcome != RenewalCandidateStaged {
		return fmt.Errorf("%w (outcome %s)", ErrNoCandidate, ref.Outcome)
	}
	return nil
}

// readRefCA reads the CA certificate and requires it to be the CA the
// candidate was staged against.
func (e machineEnv) readRefCA(ref CandidateRef) ([]byte, *x509.Certificate, error) {
	caDER, caCert, err := e.readCert(caCertFile, "CA")
	if err != nil {
		return nil, nil, err
	}
	if sha256.Sum256(caDER) != ref.CASHA256 {
		return nil, nil, fmt.Errorf("%w: CA certificate differs", ErrCandidateStale)
	}
	return caDER, caCert, nil
}

// readRefPending reads the pending candidate and requires it to be the one
// identified by ref.
func (e machineEnv) readRefPending(ref CandidateRef) (*x509.Certificate, error) {
	der, err := e.fs.readFile(e.path(pendingServerCertFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %v", ErrCandidateNotFound, err)
		}
		return nil, fmt.Errorf("read pending server certificate: %w", err)
	}
	if sha256.Sum256(der) != ref.CandidateSHA256 {
		return nil, ErrCandidateMismatch
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse pending server certificate: %w", err)
	}
	return cert, nil
}

// loadServingCandidate is the platform-independent body of
// LoadServingCandidate. It never mutates state.
func loadServingCandidate(e machineEnv, ref CandidateRef) (Material, error) {
	if err := checkStagedRef(ref); err != nil {
		return Material{}, err
	}
	caDER, caCert, err := e.readRefCA(ref)
	if err != nil {
		return Material{}, err
	}
	curDER, _, err := e.readPersistedServer()
	if err != nil {
		return Material{}, err
	}
	if sha256.Sum256(curDER) != ref.BaseSHA256 {
		return Material{}, fmt.Errorf("%w: persisted server certificate differs from the staging base", ErrCandidateStale)
	}
	cand, err := e.readRefPending(ref)
	if err != nil {
		return Material{}, err
	}
	return loadValidatedServing(e, caDER, caCert, cand)
}

// confirmServingCandidate is the platform-independent body of
// ConfirmServingCandidate.
func confirmServingCandidate(e machineEnv, ref CandidateRef) error {
	if err := checkStagedRef(ref); err != nil {
		return err
	}
	now := e.now()
	caDER, caCert, err := e.readRefCA(ref)
	if err != nil {
		return err
	}
	if err := requireTrustHealthy(e.trust, caDER); err != nil {
		return err
	}
	serverSigner, err := e.openServerKey()
	if err != nil {
		return fmt.Errorf("open server key: %w", err)
	}
	defer closeSigner(serverSigner)

	curDER, curCert, err := e.readPersistedServer()
	if err != nil {
		return err
	}
	curSHA := sha256.Sum256(curDER)

	if curSHA == ref.CandidateSHA256 {
		// Retry after a completed promotion (for example a lost response):
		// revalidate, never rewrite the backup, and never touch a pending
		// file that is not this candidate.
		if err := validateServerLeaf(curCert, caCert, serverSigner.Public(), now); err != nil {
			return fmt.Errorf("promoted server certificate failed revalidation: %w", err)
		}
		pendDER, err := e.fs.readFile(e.path(pendingServerCertFile))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return fmt.Errorf("read pending server certificate: %w", err)
		case sha256.Sum256(pendDER) == ref.CandidateSHA256:
			if err := e.fs.remove(e.path(pendingServerCertFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove promoted pending copy: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("%w: the candidate is already promoted, but a different pending candidate is present and was left untouched", ErrCandidateMismatch)
		}
	}
	if curSHA != ref.BaseSHA256 {
		return fmt.Errorf("%w: persisted server certificate differs from the staging base", ErrCandidateStale)
	}

	cand, err := e.readRefPending(ref)
	if err != nil {
		return err
	}
	if err := validateServerLeaf(cand, caCert, serverSigner.Public(), now); err != nil {
		return fmt.Errorf("pending server certificate failed revalidation: %w", err)
	}
	if !usefulCandidate(cand, curCert, now) {
		return fmt.Errorf("pending server certificate does not advance the persisted certificate")
	}

	// Single-slot backup of the current persisted certificate. It is written
	// as a copy (never by moving the current file away) and skipped when it
	// already holds exactly these bytes, which is the case on a retry after
	// a failed or interrupted promotion.
	prevPath := e.path(prevServerCertFile)
	prevDER, err := e.fs.readFile(prevPath)
	switch {
	case err == nil && bytes.Equal(prevDER, curDER):
	case err == nil || errors.Is(err, fs.ErrNotExist):
		if err := e.fs.atomicWrite(prevPath, curDER, 0600); err != nil {
			return fmt.Errorf("back up current server certificate: %w", err)
		}
	default:
		return fmt.Errorf("read server certificate backup: %w", err)
	}

	if err := e.fs.replace(e.path(pendingServerCertFile), e.path(serverCertFile)); err != nil {
		return fmt.Errorf("%w: promote pending server certificate: %w", ErrPromotionUnconfirmed, err)
	}
	return nil
}

// abandonServingCandidate is the platform-independent body of
// AbandonServingCandidate.
func abandonServingCandidate(e machineEnv, ref CandidateRef) error {
	if err := checkStagedRef(ref); err != nil {
		return err
	}
	curDER, err := e.fs.readFile(e.path(serverCertFile))
	switch {
	case err == nil:
		if sha256.Sum256(curDER) == ref.CandidateSHA256 {
			return ErrCandidatePromoted
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("read server certificate: %w", err)
	}

	pendDER, err := e.fs.readFile(e.path(pendingServerCertFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("read pending server certificate: %w", err)
	case sha256.Sum256(pendDER) != ref.CandidateSHA256:
		return ErrCandidateMismatch
	}
	if err := e.fs.remove(e.path(pendingServerCertFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove pending server certificate: %w", err)
	}
	return nil
}
