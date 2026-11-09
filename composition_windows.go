//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// ProvisionMachine performs the elevated first install of the production
// machine TLS material and verifies existing material.
//
// MUST be run elevated (Administrator). On first install (neither certificate
// DER present) it:
//   - creates or opens machine-scoped persisted CNG keys with per-role DACL
//     policies: the CA key privileged-only (SYSTEM, Administrators), the server
//     key service-signer (SYSTEM, Administrators, LOCAL SERVICE read/execute)
//   - generates self-signed CA and CA-signed server certificates
//   - persists only public certificate DERs to disk (no private-key files)
//   - installs the CA certificate in LocalMachine\Root (idempotent)
//
// The first-install server certificate is a bootstrap exception: it becomes
// the persisted server certificate without any consumer confirmation, because
// no previous certificate or consumer exists yet.
//
// ProvisionMachine never returns private-key bytes. Keys are identified by
// stable names and persist in the Microsoft Software KSP across process
// restarts.
//
// On existing, complete state it verifies the persisted material (keys,
// issuer, SANs, EKU, validity, CA trust) with the common validator and writes
// no DER. A valid leaf is returned with a nil error even within
// RenewalThreshold of expiry: success means the existing state was verified,
// not that the server certificate was renewed (renewal is StageServerRenewal
// plus consumer confirmation). An expired leaf fails with ErrRenewalDue and
// ErrCertificateNotValidNow. Existing-state keys are still acquired through
// the MachineKeyStore open-or-create seam, under the same per-role policies,
// after the open-only state check has required both keys to open; the runtime
// and renewal paths open existing keys only. A CA key whose DACL is not
// privileged-only (for example one provisioned by an earlier release) fails
// closed with ErrKeyPolicyMismatch: ProvisionMachine never migrates it; run
// MigrateMachineKeyPolicies explicitly. It does not repair trust: a missing
// or conflicting CA trust anchor fails closed with ErrTrustNotHealthy. Partial state (exactly one
// certificate DER present, or a DER whose presence cannot be determined) fails
// closed with ErrInconsistentMachineState; the CA certificate is never
// reissued for existing state.
//
// Caller contract (single writer): ProvisionMachine must be invoked by the one
// lifecycle coordinator of the machine, which must ensure that provisioning,
// cleanup/uninstall (CleanupMachine, CleanupMachineBySHA256), administrative
// recovery and every server-certificate renewal attempt (StageServerRenewal →
// LoadServingCandidate → consumer activation → ConfirmServingCandidate or
// AbandonServingCandidate) never overlap, and that no other actor creates,
// deletes or re-permissions the Local-TLS key names or state while it runs.
// Local-TLS does not implement or verify this serialization.
//
// First install is entered only after a conservative pre-check (see
// provisionPreCheck). The pre-check does not prove that the CA key is absent,
// and there is no guarantee that the CA key certified on first install was
// created by this call: the key is opened or created after the check, so an
// actor that violates the caller contract in that window can cause an existing
// key to be certified. This residual risk is accepted under the contract above.
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

	return provisionMachine(root, keyStore, trustStore, openProductionKey, callerIsPrivileged, time.Now)
}

// provisionMachine is the body of ProvisionMachine with its machine
// dependencies injected: open is the open-only key opener (openProductionKey
// in production) used by both guards, isPrivileged the caller-privilege query.
// The two guards run in order and both must pass before ProvisionWithKeyStore
// can acquire, create or certify a key, write DER or install trust.
func provisionMachine(root string, keyStore MachineKeyStore, trustStore TrustStore, open func(string) (crypto.Signer, error), isPrivileged func() (bool, error), now func() time.Time) (Material, error) {
	probe := func(name string) error { return probeOpenOnly(open, name) }

	// Pre-provision safety check. With the CA certificate missing, fail closed
	// on an existing CA key, on an ambiguous open error and for a
	// non-privileged caller; never reset or regenerate a key. Passing the check
	// does not establish that the CA key is absent ("not found or not
	// accessible" is ambiguous) and the result is not re-checked when the key is
	// opened or created; the single-writer caller contract covers that window.
	if err := provisionPreCheck(filepath.Join(root, tlsSubDir), caKeyName, probe, isPrivileged); err != nil {
		return Material{}, fmt.Errorf("provision pre-check: %w", err)
	}
	// Public-lineage machine-state check, kept in addition to the pre-check
	// above: fail closed on any partial or incoherent pre-existing production
	// state (one certificate DER without the other, certificate DERs without
	// both persisted keys, or a persisted key without certificate DERs) rather
	// than silently regenerating the CA trust anchor or creating replacement
	// keys. The check is open-only.
	if err := machineStateError(root, open); err != nil {
		return Material{}, fmt.Errorf("provision pre-check: %w", err)
	}

	return ProvisionWithKeyStore(root, keyStore, trustStore, now)
}

// productionEnv returns the machine environment used by the runtime and
// renewal paths: open-only CNG key access, read-only trust verification and
// the production file system.
func productionEnv() (machineEnv, error) {
	tlsDir, err := MachineTLSPath()
	if err != nil {
		return machineEnv{}, fmt.Errorf("resolve machine agent path: %w", err)
	}
	trustStore, err := PlatformTrustStore()
	if err != nil {
		return machineEnv{}, fmt.Errorf("platform trust store: %w", err)
	}
	return machineEnv{
		tlsDir:        tlsDir,
		openCAKey:     func() (crypto.Signer, error) { return openProductionKey(caKeyName) },
		openServerKey: func() (crypto.Signer, error) { return openProductionKey(serverKeyName) },
		trust:         trustStore,
		now:           time.Now,
		fs:            osFS,
	}, nil
}

// ReloadMachine verifies the complete production machine TLS material.
//
// ReloadMachine opens the CA private key and therefore requires a privileged
// caller (LocalSystem or an elevated Administrators member). Breaking change:
// earlier releases documented it as safe for non-elevated use because the CA
// key granted LOCAL SERVICE read/execute; the CA key is now privileged-only, so
// a non-privileged caller gets ErrPrivilegeRequired when the CA key is about to
// be opened (no key is opened before that check). It is not guaranteed to be the
// first error: the CA certificate DER is read and parsed first, and a missing or
// invalid DER is reported before the privilege check. A CA key still carrying
// the legacy DACL gets ErrKeyPolicyMismatch until
// MigrateMachineKeyPolicies is run. A non-elevated runtime (the Agent) must use
// LoadServingMaterial and LoadServingCandidate, which open only the server key.
// It:
//   - loads existing CA and server certificate DERs from disk
//   - opens (does NOT create) persisted machine-scoped CNG keys under their
//     role policies
//   - verifies cert ↔ KSP public key match for both CA and server
//   - verifies the server certificate was issued by the CA, its SANs and EKU
//   - verifies CA and server validity, including that the server certificate
//     does not outlive the CA
//   - requires CA trust state TrustHealthy (read-only verification)
//
// ReloadMachine never writes. Breaking change in v0.2.0: it no longer renews the
// server certificate. When renewal is due (within RenewalThreshold of expiry,
// or expired) it releases both signers and returns ErrRenewalDue; an already
// expired certificate additionally matches ErrCertificateNotValidNow. Use
// StageServerRenewal and the consumer confirmation flow to renew; use
// LoadServingMaterial for serving.
//
// ReloadMachine never mutates LocalMachine\Root. If the CA trust anchor is
// missing or a conflicting certificate exists, ReloadMachine fails closed.
func ReloadMachine() (Material, error) {
	env, err := productionEnv()
	if err != nil {
		return Material{}, err
	}
	return reloadExisting(env, reportRenewalDue)
}

// LoadServingMaterial loads only the TLS material required for HTTPS
// serving from the persisted server certificate. Unlike ReloadMachine, it
// does NOT open the CA private key. It never renews and never writes.
//
// It loads:
//   - CA certificate from disk (public DER only)
//   - server certificate from disk (public DER only)
//   - server private key via CNG (openProductionKey, read-only)
//
// It verifies:
//   - server cert ↔ server KSP public key match
//   - server cert was issued by the public CA, SANs and server-auth EKU
//   - CA and server certificate validity at the current time, the server
//     certificate not outliving the CA, and chain verification to the CA
//   - CA trust state TrustHealthy via read-only TrustVerifier
//
// An expired server certificate, or a missing or conflicting trust anchor,
// fails closed (ErrCertificateNotValidNow, ErrTrustNotHealthy).
//
// LoadServingMaterial never mutates LocalMachine\Root and never
// accesses the CA private key. It is the function the HTTPS listener
// MUST use for normal runtime startup.
//
// The server key is opened under the service-signer policy, which a LOCAL
// SERVICE runtime may open; it needs no privilege and is not affected by the
// CA key policy or its migration. A server key whose DACL is not exactly the
// service-signer form fails closed with ErrKeyPolicyMismatch. If the caller
// cannot open the server key (e.g., running as a user without LocalService
// rights), it fails closed.
func LoadServingMaterial() (Material, error) {
	env, err := productionEnv()
	if err != nil {
		return Material{}, err
	}
	return loadServing(env)
}

// StageServerRenewal prepares a server-certificate renewal without changing
// the persisted server certificate.
//
// It verifies the CA (validity, key match, TrustHealthy) and the identity of
// the persisted server certificate (key match, issuer, SANs, EKU; an expired
// previous leaf is accepted as the renewal base). When renewal is not due it
// returns a CandidateRef with Outcome RenewalNotDue and writes nothing. When
// renewal is due it reuses a valid, useful pending candidate, or issues a new
// leaf for the existing server key signed by the existing CA key, validates
// it, and persists it as the pending candidate. It fails with
// ErrLeafOutlivesCA rather than issue a leaf that would outlive the CA.
//
// Stage opens the existing CA and server keys only (never creates them),
// never installs trust and never rotates keys or the CA. Because it signs with
// the privileged-only CA key it requires a privileged caller
// (ErrPrivilegeRequired otherwise) and a migrated CA key (ErrKeyPolicyMismatch
// otherwise); it is a renewal-authority operation, not an Agent one. It replaces an
// invalid or stale pending candidate, so it must not run while a consumer
// attempt for an earlier candidate is in progress (single-writer contract).
// A staged candidate is not active and not served by LoadServingMaterial.
func StageServerRenewal() (CandidateRef, error) {
	env, err := productionEnv()
	if err != nil {
		return CandidateRef{}, err
	}
	return stageServerRenewal(env)
}

// LoadServingCandidate loads the staged candidate identified by ref as serving
// Material, for the consumer to activate in its listener. It verifies that
// the CA and persisted server certificate are still the ones ref was staged
// against, that the pending candidate is exactly ref's candidate, and applies
// the same validation and TrustHealthy check as LoadServingMaterial. It opens
// only the server key and never writes. The caller owns the returned Material
// and must Close it when no handshake can use it any longer.
//
// Loading a candidate does not activate it. Activation in a listener and the
// attestation that the listener serves it are the consumer's responsibility.
func LoadServingCandidate(ref CandidateRef) (Material, error) {
	env, err := productionEnv()
	if err != nil {
		return Material{}, err
	}
	return loadServingCandidate(env, ref)
}

// ConfirmServingCandidate requests promotion of the staged candidate to the
// persisted server certificate, after the consumer has activated it and has
// itself attested that its listener serves it.
//
// Confirm is a promotion request, not proof of activation: Local-TLS cannot
// observe the listener and never claims that it switched. Before promoting it
// revalidates the CA, trust, the candidate (validity, key, chain) and the
// base/candidate/CA digests in ref, writes a single-slot backup of the current
// persisted certificate (server-cert.prev.der), then replaces the persisted
// certificate with the candidate.
//
// A retry with the same ref after a completed promotion (for example after a
// lost response) is recognised and never rewrites the backup. It returns nil
// only while the promoted certificate still passes validation (CA, trust,
// time) and no different pending candidate is present; otherwise it fails
// without changing anything. Retries are idempotent in their effect on disk,
// not guaranteed to succeed.
// ErrPromotionUnconfirmed means the outcome of the final replace is unknown;
// retry with the same ref to reconcile. A backup may already have been written
// before any failure of the final replace. Stale or mismatched state fails with
// ErrCandidateStale or ErrCandidateMismatch without changing anything.
func ConfirmServingCandidate(ref CandidateRef) error {
	env, err := productionEnv()
	if err != nil {
		return err
	}
	return confirmServingCandidate(env, ref)
}

// AbandonServingCandidate deletes the pending candidate identified by ref.
// It is an idempotent no-op when no pending candidate exists, and fails with
// ErrCandidateMismatch (deleting nothing) when the pending candidate is a
// different one, and with ErrCandidatePromoted when ref's candidate is already
// the persisted server certificate.
//
// Abandon does not reverse a listener activation (the consumer restores its
// previous Material itself) and never reverses a completed promotion; recovery
// after promotion is administrative (see README). It needs no keys and does
// not touch trust.
func AbandonServingCandidate(ref CandidateRef) error {
	env, err := productionEnv()
	if err != nil {
		return err
	}
	return abandonServingCandidate(env, ref)
}

// MigrateMachineKeyPolicies is the explicit, privileged, idempotent and
// tighten-only migration of the persisted production key DACLs to the
// per-role policies (see keyPolicy). It exists for installations provisioned
// before the CA key was separated from the server signer, whose CA key still
// grants LOCAL SERVICE read/execute.
//
// It MUST be run by a LocalSystem or elevated Administrators caller (otherwise
// ErrPrivilegeRequired, no key touched) and only on complete provisioned state
// (both certificate DERs present). It:
//   - verifies, read-only, that the server key opens under the service-signer
//     policy and matches the persisted server certificate (the server DACL is
//     never rewritten);
//   - rewrites the CA key DACL in place from the exact service-signer form to
//     privileged-only, with read-back on the open and on a fresh handle; a CA
//     key already privileged-only is left untouched (idempotent);
//   - verifies that the CA key opens under the privileged-only policy and
//     matches the persisted CA certificate, and that the CA certificate DER is
//     unchanged.
//
// It never creates, regenerates, rotates or deletes a key, never writes a
// certificate and never reads or mutates LocalMachine\Root. Any other DACL, a
// key that does not open (ErrKeyNotFound is not proof of absence), a key that
// does not match its certificate or any ambiguous state fails closed. A failure
// after the CA DACL write leaves the tightened DACL in place; it is never
// rolled back, since that would widen access.
//
// Local-TLS never runs this migration implicitly: serving and verification
// paths fail with ErrKeyPolicyMismatch on a legacy CA key instead. Single
// writer: the lifecycle coordinator must not run it concurrently with
// provisioning, renewal or cleanup.
func MigrateMachineKeyPolicies() error {
	tlsDir, err := MachineTLSPath()
	if err != nil {
		return fmt.Errorf("resolve machine agent path: %w", err)
	}
	return migrateKeyPolicies(keyPolicyMigration{
		tlsDir:        tlsDir,
		fs:            osFS,
		isPrivileged:  callerIsPrivileged,
		openServerKey: func() (crypto.Signer, error) { return openProductionKey(serverKeyName) },
		tightenCAKey:  tightenCAKeyPolicy,
		openCAKey:     func() (crypto.Signer, error) { return openProductionKey(caKeyName) },
	})
}

// closeProductionSigner closes a CNG signer if it implements the closer
// interface. It is best-effort: the CNG signer's Close may report a failure to
// release a native handle (only on the first call, never retried), but the
// returned error is discarded; the open-only probes that use it report only
// whether the key opened.
func closeProductionSigner(s crypto.Signer) {
	_ = closeSigner(s)
}

// probeOpenOnly opens the exact persisted key through the open-only opener
// (openProductionKey in production) without creating it and releases it
// immediately. It reports only whether the open succeeded; see
// provisionPreCheck for how its errors are interpreted.
func probeOpenOnly(open func(string) (crypto.Signer, error), name string) error {
	signer, err := open(name)
	if err != nil {
		return err
	}
	closeProductionSigner(signer)
	return nil
}

// machineStateError is the classifying form of checkInconsistentMachineState
// used by provisionMachine. It returns nil for a true first install (no
// certificate DER and no openable persisted key) and for a complete state
// (both certificate DERs and both persisted keys openable). Every partial or
// incoherent state returns an error wrapping ErrInconsistentMachineState. An
// unexpected open failure (permission, invalid/security-invalid persisted key,
// or other CNG error) is returned unchanged so the caller fails closed; the
// server key is not probed after an unexpected CA key failure.
//
// When both certificate DERs are present and a key does not open, the key's
// open error stays in the returned chain: it matches ErrKeyNotFound and keeps
// the key name and native HRESULT text. That result is diagnostic context
// only. ErrKeyNotFound means "not found or not accessible" and is never taken
// as proof that the key is absent; without certificate DERs it is accepted
// only after provisionPreCheck has required a privileged caller. The key probe
// is open-only, so the check can never create a key.
func machineStateError(root string, open func(string) (crypto.Signer, error)) error {
	tlsDir := filepath.Join(root, tlsSubDir)
	caDER := fileExists(filepath.Join(tlsDir, caCertFile))
	serverDER := fileExists(filepath.Join(tlsDir, serverCertFile))

	// Partial certificate state: one DER present without the other. This is
	// already inconsistent; there is no need to probe the key store.
	if caDER != serverDER {
		return inconsistentMaterialError(tlsDir, "exactly one certificate DER is present")
	}

	// Probe both keys (open-only). Both must open for a complete state, and
	// neither may open for a true first install.
	caKey, caCause, err := probeKeyCause(open, caKeyName)
	if err != nil {
		return err
	}
	serverKey, serverCause, err := probeKeyCause(open, serverKeyName)
	if err != nil {
		return err
	}
	if !provisionStateInconsistent(caDER, serverDER, caKey, serverKey) {
		return nil
	}

	if !caDER {
		var opened []string
		if caKey {
			opened = append(opened, caKeyName)
		}
		if serverKey {
			opened = append(opened, serverKeyName)
		}
		return inconsistentMaterialError(tlsDir, fmt.Sprintf("no certificate DER is present but persisted key(s) %q opened", opened))
	}
	return inconsistentMaterialError(tlsDir, "both certificate DERs are present but a persisted key did not open", caCause, serverCause)
}

// inconsistentMaterialError builds the ErrInconsistentMachineState error for
// provisionMachine. Non-nil causes (the failed key opens) are kept in the
// chain so callers can still inspect them.
func inconsistentMaterialError(tlsDir, detail string, causes ...error) error {
	err := fmt.Errorf(
		"%w: existing production material is incomplete or incoherent in %s (%s) — "+
			"automatic CA regeneration is forbidden to prevent duplicate trust anchors; "+
			"restore the missing material or perform a full re-provisioning cleanup",
		ErrInconsistentMachineState, tlsDir, detail,
	)
	if cause := errors.Join(causes...); cause != nil {
		return fmt.Errorf("%w: %w", err, cause)
	}
	return err
}

// checkInconsistentMachineState reports whether the production machine state is
// inconsistent (partial or incoherent) and must fail closed instead of being
// silently re-provisioned. It is the boolean view of machineStateError: an
// inconsistent state reports true with a nil error, and an unexpected open
// failure is returned as the error.
func checkInconsistentMachineState(root string, open func(string) (crypto.Signer, error)) (bool, error) {
	err := machineStateError(root, open)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, ErrInconsistentMachineState):
		return true, nil
	default:
		return false, err
	}
}

// probeKey probes a persisted production key using an open-only operation and
// reports whether it opened. ErrKeyNotFound ("not found or not accessible")
// reports false without proving absence; unexpected open failures
// (permission, invalid/security-invalid persisted key, or other CNG errors) are
// returned so the caller fails closed. The open operation never creates a key.
func probeKey(open func(string) (crypto.Signer, error), name string) (bool, error) {
	opened, _, err := probeKeyCause(open, name)
	return opened, err
}

// probeKeyCause is probeKey that also returns the ErrKeyNotFound open error
// (with its key name and native HRESULT) when the key did not open, so a caller
// can keep it as diagnostic context. An opened key is closed immediately.
func probeKeyCause(open func(string) (crypto.Signer, error), name string) (opened bool, notFound, err error) {
	signer, err := open(name)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return false, err, nil
		}
		return false, nil, err
	}
	closeProductionSigner(signer)
	return true, nil, nil
}
