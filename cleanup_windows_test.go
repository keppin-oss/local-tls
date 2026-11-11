//go:build windows

package localtls

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/local-tls/internal/identity"
)

// TestProductionKeyNamesExact proves the cleanup operates on the exact
// Local-TLS production key names and never on the test/smoke namespace or on
// Machine Identity / Enterprise identities.
func TestProductionKeyNamesExact(t *testing.T) {
	if caKeyName != identity.ProdCAKeyName {
		t.Fatalf("caKeyName = %q, want %q", caKeyName, identity.ProdCAKeyName)
	}
	if serverKeyName != identity.ProdServerKeyName {
		t.Fatalf("serverKeyName = %q, want %q", serverKeyName, identity.ProdServerKeyName)
	}

	for _, name := range []string{caKeyName, serverKeyName} {
		if strings.HasPrefix(name, identity.TestKeyNamespace) {
			t.Errorf("production key %q must not live in the test namespace %q", name, identity.TestKeyNamespace)
		}
		if strings.HasPrefix(name, identity.SmokeKeyNamespace) {
			t.Errorf("production key %q must not live in the smoke namespace %q", name, identity.SmokeKeyNamespace)
		}
	}
}

func TestPlatformKeyDeleterReturnsDeleter(t *testing.T) {
	d, err := PlatformKeyDeleter()
	if err != nil {
		t.Fatalf("PlatformKeyDeleter: %v", err)
	}
	if d == nil {
		t.Fatal("PlatformKeyDeleter returned nil")
	}
	if _, ok := d.(MachineKeyDeleter); !ok {
		t.Fatal("returned value does not implement MachineKeyDeleter")
	}
}

// TestCleanupLifecycleElevated proves the full provision → verify → release →
// cleanup → post-cleanup check lifecycle against test-only smoke namespaces
// (cleanup is confirmed by successful deletes, never by a not-found re-open),
// and repeats it to prove repeatability. It requires Administrator elevation
// and a diagnostics directory outside the test temporary directory
// (KEPPIN_SMOKE_DIAG_DIR); it is skipped (reported NOT EXECUTED), before any
// machine operation, when either prerequisite is absent.
//
// Once the prerequisites are established, every operational failure
// (provision, verification, release, cleanup, or post-cleanup validation) fails
// the test rather than being converted into a skip. After a failed release no
// key is deleted.
func TestCleanupLifecycleElevated(t *testing.T) {
	diagDir := os.Getenv(smokeDiagDirEnv)
	if diagDir == "" {
		t.Skipf("elevated lifecycle smoke requires %s to name an existing diagnostics directory outside the test temporary directory — NOT EXECUTED", smokeDiagDirEnv)
	}
	if fi, err := os.Stat(diagDir); err != nil || !fi.IsDir() {
		t.Skipf("%s=%q is not an existing directory (%v) — NOT EXECUTED", smokeDiagDirEnv, diagDir, err)
	}

	unavailable, err := establishSmokeElevation()
	if unavailable {
		t.Skipf("elevated lifecycle smoke requires Administrator: %v — NOT EXECUTED", err)
	}
	if err != nil {
		t.Fatalf("elevation probe failed: %v", err)
	}

	if err := runSmokeLifecycles(t, nativeSmokeLifecycleOps(), diagDir); err != nil {
		t.Fatal(err)
	}
}

// smokeElevationDeps are the key operations establishSmokeElevation uses. The
// elevated test uses TestOpenKey, TestCreateKey and TestDeleteKey; offline
// tests substitute fakes so the SKIP/FAIL classification is covered without
// touching a machine key.
type smokeElevationDeps struct {
	name   func() (string, error)
	open   func(string) (crypto.Signer, error)
	create func(string) (crypto.Signer, error)
	del    func(string) error
}

// establishSmokeElevation verifies the elevated CNG prerequisite by creating
// and deleting a disposable, uniquely-named smoke-namespace test key.
func establishSmokeElevation() (unavailable bool, err error) {
	return establishSmokeElevationWith(smokeElevationDeps{
		name:   uniqueSmokeProbeName,
		open:   TestOpenKey,
		create: TestCreateKey,
		del:    TestDeleteKey,
	})
}

// establishSmokeElevationWith is the body of establishSmokeElevation.
//
// It returns two values that distinguish the two failure classes:
//
//   - unavailable == true: the elevation prerequisite (Administrator CNG write
//     access) is explicitly absent: creating the probe key was denied and CNG
//     reported no failed cleanup of a key created by that call. The caller
//     should SKIP.
//   - unavailable == false && err != nil: an operational failure occurred (for
//     example a signer-close or key-deletion failure after the key was
//     created) — the caller must FAIL.
//
// The probe key name is fresh and random, and an open-only preflight must
// report ErrKeyNotFound before the key is created. ErrKeyNotFound means "not
// found or not accessible", so the preflight does not prove absence; the
// random name is what makes a pre-existing key with that name implausible. A
// key that opens is never reused or deleted, and any other preflight error is
// operational.
//
// Cleanup is confirmed only by a successful delete. A delete that reports
// ErrKeyNotFound did not delete anything and is an operational failure
// (ErrKeyDeletionUnconfirmed), never a skip and never a success.
func establishSmokeElevationWith(deps smokeElevationDeps) (unavailable bool, err error) {
	probeName, err := deps.name()
	if err != nil {
		return false, err
	}

	// Open-only preflight on the fresh name.
	if err := probeKeyOwnership(deps.open, probeName); err != nil {
		return false, err
	}

	// Create the probe key. Only a denied create is the missing prerequisite.
	// A create error does not prove that no key was created: when CNG reports
	// that deleting the key created by the failed call also failed, that key
	// may persist under the exact probe name. That is an operational failure
	// and takes precedence over the text-based prerequisite check (the
	// access-denied text may belong to either part). Nothing is deleted here:
	// the error names the exact probe key for inspection.
	signer, err := deps.create(probeName)
	if err != nil {
		if createCleanupFailed(err) {
			return false, fmt.Errorf("create elevation probe key %q failed and the key created by that call may persist (CNG cleanup failed); inspect and remove that exact key: %w", probeName, err)
		}
		if isElevationUnavailable(err) {
			return true, err
		}
		return false, err
	}

	// The probe key was created by this call. Any failure from here on is
	// operational and must fail the test. The key is deleted only after its
	// signer was released. When Close fails, the release of the native handle
	// is not confirmed, so the key is not deleted: the
	// error keeps the close cause and names the exact key for an authorized
	// manual removal after the test process exits.
	if cerr := closeSigner(signer); cerr != nil {
		return false, fmt.Errorf("close elevation probe key %q: %w: %w; the key is not deleted, remove that exact key only through an authorized manual recovery after the test process exits", probeName, errSmokeReleaseUnconfirmed, cerr)
	}

	if delErr := deps.del(probeName); delErr != nil {
		return false, keyCleanupError(fmt.Sprintf("delete elevation probe key %q", probeName), delErr)
	}
	return false, nil
}

// createCleanupFailed reports whether a create error says that the key created
// by the failed call could not be deleted (windowscng.ErrCleanupFailed). The
// sentinel is matched in the chain and, because mapCNGError flattens a chain
// that also carries windowscng.ErrKeyNotFound into text, by its exact message.
func createCleanupFailed(err error) bool {
	return errors.Is(err, windowscng.ErrCleanupFailed) || strings.Contains(err.Error(), windowscng.ErrCleanupFailed.Error())
}

// isElevationUnavailable reports whether err indicates the process lacks the
// Administrator elevation required to create a machine-scoped CNG key. It
// recognizes the CNG access-denied HRESULTs and messages the shared windowscng
// layer surfaces when a non-elevated caller attempts to create a machine key.
func isElevationUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, ind := range []string{
		"access is denied",
		"access denied",
		"0x80090010", // NTE_PERM
		"0x801f0005", // STATUS_ACCESS_DENIED
	} {
		if strings.Contains(msg, ind) {
			return true
		}
	}
	return false
}

// uniqueSmokeProbeName returns a fresh, unique test-only key name under the
// smoke namespace. It never returns a fixed or reusable fixture name.
func uniqueSmokeProbeName() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate elevation probe suffix: %w", err)
	}
	return identity.SmokeKeyNamespace + "elevation-probe-" + hex.EncodeToString(buf[:]), nil
}

// probeKeyOwnership classifies the open-only preflight for a unique probe key
// name. It returns nil only for ErrKeyNotFound ("not found or not accessible";
// not a proof of absence, see establishSmokeElevationWith). A key that
// unexpectedly opens is closed, never deleted, and reported as an error,
// together with any failure to release its signer. Any other open error is
// returned wrapped.
func probeKeyOwnership(open func(string) (crypto.Signer, error), name string) error {
	signer, err := open(name)
	if err == nil {
		err := fmt.Errorf("elevation probe key %q unexpectedly already exists; it is not owned by this test and is left untouched", name)
		if cerr := closeSigner(signer); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close the signer of the existing key %q: %w", name, cerr))
		}
		return err
	}
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	}
	return fmt.Errorf("open elevation probe key %q: %w", name, err)
}

// errSmokeReleaseUnconfirmed marks a signer whose Close failed: the release of
// its native handle is not confirmed. The key the
// signer was opened on is then not deleted; it is left for an authorized manual
// recovery after the test process exits, and the run stops.
var errSmokeReleaseUnconfirmed = errors.New("signer release not confirmed")

// errSmokeIdentityUnrecovered marks a run whose CA DER could not be read, so
// the trust anchor it may have installed is neither identified nor removed
// automatically.
var errSmokeIdentityUnrecovered = errors.New("smoke CA identity not recovered")

// smokeDiagDirEnv names an existing directory, outside the test temporary
// directory, where the elevated lifecycle smoke writes the diagnostics of a run
// that did not complete. TestCleanupLifecycleElevated does not run without it.
const smokeDiagDirEnv = "KEPPIN_SMOKE_DIAG_DIR"

// smokeLifecycleOps are the machine operations of one smoke lifecycle run. The
// elevated test uses nativeSmokeLifecycleOps; offline tests substitute fakes.
type smokeLifecycleOps struct {
	open        func(name string) (crypto.Signer, error)
	provision   func(rootDir string) (Material, error)
	verifyTrust func(caCertDER []byte) (TrustState, error)
	removeTrust func(caCertDER []byte) error
	isTrusted   func(fingerprint [32]byte) (bool, error)
	del         func(name string) error
}

func nativeSmokeLifecycleOps() smokeLifecycleOps {
	return smokeLifecycleOps{
		open:        TestOpenKey,
		provision:   ProvisionSmoke,
		verifyTrust: VerifySmokeTrust,
		removeTrust: func(caCertDER []byte) error {
			store, err := PlatformTrustStore()
			if err != nil {
				return fmt.Errorf("PlatformTrustStore: %w", err)
			}
			return store.RemoveTrust(caCertDER)
		},
		isTrusted: func(fingerprint [32]byte) (bool, error) {
			store, err := PlatformTrustStore()
			if err != nil {
				return false, fmt.Errorf("PlatformTrustStore: %w", err)
			}
			return store.IsTrustedSHA256(fingerprint)
		},
		del: TestDeleteKey,
	}
}

// smokeHarness is the part of *testing.T a lifecycle run uses. Offline tests
// pass a real subtest, so t.TempDir and t.Cleanup keep their real ordering,
// and capture the reported errors instead of failing.
type smokeHarness interface {
	TempDir() string
	Cleanup(func())
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
}

// smokeOwnershipPreflight requires every fixed smoke key name to report
// ErrKeyNotFound before the run, so that the keys the run deletes are the ones
// it created. ErrKeyNotFound means "not found or not accessible" and is not a
// proof of absence; the test is meant for a dedicated machine without other
// writers. A key that opens is closed, never deleted, and fails the preflight
// together with any failure to release its signer; any other open error fails
// it too. A refused run registers no cleanup.
func smokeOwnershipPreflight(open func(string) (crypto.Signer, error), names ...string) error {
	for _, name := range names {
		signer, err := open(name)
		if err == nil {
			err := fmt.Errorf("smoke key %q already opens before the run; it is not owned by this test and is left untouched. STOP: inspect the dedicated test machine and remove that key only through an authorized manual recovery", name)
			if cerr := closeSigner(signer); cerr != nil {
				err = errors.Join(err, fmt.Errorf("close the signer of the existing smoke key %q: %w", name, cerr))
			}
			return err
		}
		if !errors.Is(err, ErrKeyNotFound) {
			return fmt.Errorf("smoke ownership preflight: open smoke key %q: %w", name, err)
		}
	}
	return nil
}

// smokeOutcome is the cleanup state of one test-owned artifact.
type smokeOutcome int

const (
	smokeNotAttempted    smokeOutcome = iota
	smokeConfirmed                    // removed, or (trust anchor only) already absent
	smokeFailed                       // attempted and not confirmed
	smokeSkippedByPolicy              // not attempted: the signer release is not confirmed
)

func (o smokeOutcome) String() string {
	switch o {
	case smokeConfirmed:
		return "confirmed"
	case smokeFailed:
		return "FAILED"
	case smokeSkippedByPolicy:
		return "NOT ATTEMPTED by policy"
	default:
		return "not attempted"
	}
}

// smokeArtifact records the single cleanup attempt of one artifact.
type smokeArtifact struct {
	outcome smokeOutcome
	note    string
	err     error
}

func (a smokeArtifact) String() string {
	s := a.outcome.String()
	if a.note != "" {
		s += " (" + a.note + ")"
	}
	if a.err != nil {
		s += ": " + a.err.Error()
	}
	return s
}

// smokeRun tracks the test-owned artifacts of one lifecycle run and the
// outcome of every cleanup operation on them. Each operation is attempted at
// most once per run: the fallback acts only on artifacts nobody attempted yet
// and reports, without retrying, those that failed.
type smokeRun struct {
	tlsDir  string
	diagDir string
	ops     smokeLifecycleOps
	h       smokeHarness

	material       *Material // nil until provisioning returns Material
	closeAttempted bool
	closeErr       error // persistent: the release stays unconfirmed

	caDER       []byte // exact CA identity of the run, when known
	identityErr error

	trust, caKey, serverKey, dir smokeArtifact
	cleanupErr                   error // the error cleanupLocalTLS returned, kept for the diagnostics

	cleaned   bool // trust anchor, both keys and the state directory confirmed
	succeeded bool // the whole cycle, postconditions included, completed
}

// closeMaterial releases the serving signer at most once. A failed release is
// never retried and its error is returned again on every later call, so that
// nothing treats the signer as released.
func (r *smokeRun) closeMaterial() error {
	if r.material == nil {
		return nil
	}
	if !r.closeAttempted {
		r.closeAttempted = true
		if err := r.material.Close(); err != nil {
			r.closeErr = fmt.Errorf("close smoke material: %w: %w", errSmokeReleaseUnconfirmed, err)
		}
	}
	return r.closeErr
}

// keyDeletionBlocked returns why no smoke key may be deleted now: the serving
// signer was not released yet, or its release failed.
func (r *smokeRun) keyDeletionBlocked() error {
	if r.material == nil {
		return nil
	}
	if !r.closeAttempted {
		return errors.New("the serving signer was not released before key deletion")
	}
	return r.closeErr
}

// deleteKey deletes one smoke key by exact name, at most once per run.
func (r *smokeRun) deleteKey(name string, a *smokeArtifact) error {
	if a.outcome != smokeNotAttempted {
		return a.err
	}
	if err := r.keyDeletionBlocked(); err != nil {
		a.outcome = smokeSkippedByPolicy
		a.err = fmt.Errorf("smoke key %q not deleted: %w", name, err)
		return a.err
	}
	if err := r.ops.del(name); err != nil {
		a.outcome, a.err = smokeFailed, err
		return err
	}
	a.outcome = smokeConfirmed
	return nil
}

// removeTrustOnce removes the trust anchor of the exact CA DER, at most once
// per run. An absent anchor is a confirmed postcondition.
func (r *smokeRun) removeTrustOnce(caCertDER []byte) error {
	if r.trust.outcome != smokeNotAttempted {
		return r.trust.err
	}
	err := r.ops.removeTrust(caCertDER)
	switch {
	case err == nil:
		r.trust.outcome = smokeConfirmed
	case errors.Is(err, ErrTrustAnchorNotFound):
		r.trust.outcome, r.trust.note = smokeConfirmed, "already absent"
	default:
		r.trust.outcome, r.trust.err = smokeFailed, err
	}
	return err
}

// smokeRunKeyDeleter routes the key deletions of cleanupLocalTLS through the
// run, so the production cleanup is reused and its per-key outcome observed.
type smokeRunKeyDeleter struct{ r *smokeRun }

func (d smokeRunKeyDeleter) DeleteCAKey() error {
	return d.r.deleteKey(SmokeCAKeyName, &d.r.caKey)
}

func (d smokeRunKeyDeleter) DeleteServerKey() error {
	return d.r.deleteKey(SmokeServerKeyName, &d.r.serverKey)
}

// observeDir records whether cleanupLocalTLS removed the state directory.
func (r *smokeRun) observeDir() {
	_, err := os.Stat(r.tlsDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.dir = smokeArtifact{outcome: smokeConfirmed}
	case err != nil:
		r.dir = smokeArtifact{outcome: smokeFailed, err: fmt.Errorf("stat TLS state directory %q: %w", r.tlsDir, err)}
	default:
		r.dir = smokeArtifact{outcome: smokeFailed, err: fmt.Errorf("TLS state directory %q still present after cleanup", r.tlsDir)}
	}
}

// identity returns the exact CA DER whose trust anchor the run may have
// installed: the provisioned Material's or, when provisioning failed part-way,
// the persisted ca-cert.der (first install writes the DER before installing
// trust). An absent file means the run installed no trust anchor. An
// unreadable file leaves the identity unrecovered.
func (r *smokeRun) identity() ([]byte, error) {
	if r.caDER != nil || r.identityErr != nil {
		return r.caDER, r.identityErr
	}
	path := filepath.Join(r.tlsDir, caCertFile)
	der, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		r.identityErr = fmt.Errorf("%w: read %s: %w", errSmokeIdentityUnrecovered, path, err)
	default:
		r.caDER = der
	}
	return r.caDER, r.identityErr
}

// fallback handles a run that did not complete. It runs from t.Cleanup, before
// the t.TempDir removal (cleanups run last-in, first-out). Unless the cleanup
// was already confirmed, it releases the serving signer if nobody did, removes
// the trust anchor of the exact CA DER if nobody attempted it, and deletes the
// smoke keys nobody attempted, unless the signer release is not confirmed
// (then no key is deleted). It never retries a failed operation. It
// returns every unresolved artifact and writes the diagnostics outside the
// temporary directory.
func (r *smokeRun) fallback() []error {
	if r.succeeded {
		return nil
	}
	if !r.cleaned {
		_ = r.closeMaterial()
		if der, err := r.identity(); err == nil && der != nil {
			_ = r.removeTrustOnce(der)
		}
		_ = r.deleteKey(SmokeCAKeyName, &r.caKey)
		_ = r.deleteKey(SmokeServerKeyName, &r.serverKey)
	}
	errs := r.unresolved()
	if err := r.writeDiagnostics(); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// unresolved returns one error per artifact the run could not confirm.
func (r *smokeRun) unresolved() []error {
	var errs []error
	if r.closeErr != nil {
		errs = append(errs, r.closeErr)
	}
	if r.identityErr != nil {
		errs = append(errs, fmt.Errorf("%w; its trust anchor, if any, was not removed", r.identityErr))
	}
	if r.trust.outcome == smokeFailed {
		errs = append(errs, fmt.Errorf("remove smoke trust anchor (CA SHA-256 %x): %w", sha256.Sum256(r.caDER), r.trust.err))
	}
	for _, k := range []struct {
		name string
		a    smokeArtifact
	}{{SmokeCAKeyName, r.caKey}, {SmokeServerKeyName, r.serverKey}} {
		switch k.a.outcome {
		case smokeFailed:
			errs = append(errs, keyCleanupError(fmt.Sprintf("delete smoke key %q", k.name), k.a.err))
		case smokeSkippedByPolicy:
			errs = append(errs, k.a.err)
		}
	}
	if r.dir.outcome == smokeFailed {
		errs = append(errs, r.dir.err)
	}
	return errs
}

// diagnostics describes the state a run that did not complete left behind.
func (r *smokeRun) diagnostics() string {
	var b strings.Builder
	b.WriteString("smoke lifecycle run did not complete. STOP: do not start another run before an authorized recovery.\n")
	switch {
	case r.identityErr != nil:
		fmt.Fprintf(&b, "CA identity: NOT RECOVERED: %v\n", r.identityErr)
	case r.caDER != nil:
		fmt.Fprintf(&b, "CA identity: SHA-256 %x\n", sha256.Sum256(r.caDER))
	default:
		b.WriteString("CA identity: no CA DER was written (the run installed no trust anchor)\n")
	}
	switch {
	case r.material == nil:
		b.WriteString("serving signer close: not applicable (provisioning returned no Material)\n")
	case !r.closeAttempted:
		b.WriteString("serving signer close: not attempted\n")
	case r.closeErr != nil:
		fmt.Fprintf(&b, "serving signer close: FAILED, release not confirmed: %v\n", r.closeErr)
	default:
		b.WriteString("serving signer close: confirmed\n")
	}
	fmt.Fprintf(&b, "trust anchor: %v\n", r.trust)
	fmt.Fprintf(&b, "key %s: %v\n", SmokeCAKeyName, r.caKey)
	fmt.Fprintf(&b, "key %s: %v\n", SmokeServerKeyName, r.serverKey)
	fmt.Fprintf(&b, "state directory %s: %v\n", r.tlsDir, r.dir)
	if r.cleanupErr != nil {
		fmt.Fprintf(&b, "main cleanup error: %v\n", r.cleanupErr)
	}
	return b.String()
}

// writeDiagnostics logs the diagnostics and, when diagDir is set, writes them
// and the exact CA DER there, outside the temporary directory that t.TempDir
// removes after the fallback.
func (r *smokeRun) writeDiagnostics() error {
	report := r.diagnostics()
	r.h.Logf("%s", report)
	if r.diagDir == "" {
		return nil
	}
	base := filepath.Join(r.diagDir, fmt.Sprintf("smoke-diag-%d", time.Now().UnixNano()))
	var errs []error
	if err := os.WriteFile(base+".txt", []byte(report), 0o600); err != nil {
		errs = append(errs, fmt.Errorf("write smoke diagnostics: %w", err))
	}
	if r.caDER != nil {
		if err := os.WriteFile(base+"-ca.der", r.caDER, 0o600); err != nil {
			errs = append(errs, fmt.Errorf("write smoke CA DER: %w", err))
		}
	}
	return errors.Join(errs...)
}

// runSmokeLifecycle executes one full provision → verify → release → cleanup
// → post-cleanup check cycle against disposable test-owned artifacts.
//
// It first checks that neither fixed smoke key name opens; a refused run
// registers no cleanup. It then registers the fallback before provisioning, so
// that a failure at any later point, including a part-way provisioning
// failure, is handled by smokeRun.fallback. The serving signer is released
// before any key deletion; when that release fails, no key is deleted.
func runSmokeLifecycle(h smokeHarness, ops smokeLifecycleOps, diagDir string) error {
	root := h.TempDir()
	run := &smokeRun{tlsDir: filepath.Join(root, tlsSubDir), diagDir: diagDir, ops: ops, h: h}

	if err := smokeOwnershipPreflight(ops.open, SmokeCAKeyName, SmokeServerKeyName); err != nil {
		return err
	}
	h.Cleanup(func() {
		for _, err := range run.fallback() {
			h.Errorf("fallback cleanup: %v", err)
		}
	})

	material, err := ops.provision(root)
	if err != nil {
		return fmt.Errorf("ProvisionSmoke: %w", err)
	}
	run.material = &material
	run.caDER = material.CACertificate.Raw
	// Recorded in the test log for manual anchor recovery
	// (CleanupSmokeAnchorBySHA256) if the automatic cleanup fails.
	h.Logf("smoke CA SHA-256: %x", material.CAFingerprintSHA256)

	state, err := ops.verifyTrust(material.CACertificate.Raw)
	if err != nil {
		return fmt.Errorf("VerifySmokeTrust: %w", err)
	}
	if state != TrustHealthy {
		return fmt.Errorf("expected TrustHealthy, got %s", state)
	}

	// Release the serving signer before deleting the key it was opened from.
	if err := run.closeMaterial(); err != nil {
		return err
	}

	// cleanupLocalTLS returns nil only when both key deletes succeeded; an
	// ErrKeyNotFound delete is ErrKeyDeletionUnconfirmed and fails here.
	err = cleanupLocalTLS(run.tlsDir, smokeRunKeyDeleter{run}, func() error {
		return run.removeTrustOnce(material.CACertificate.Raw)
	})
	run.observeDir()
	if err != nil {
		run.cleanupErr = err
		return fmt.Errorf("cleanupLocalTLS: %w", err)
	}
	run.cleaned = run.trust.outcome == smokeConfirmed && run.caKey.outcome == smokeConfirmed &&
		run.serverKey.outcome == smokeConfirmed && run.dir.outcome == smokeConfirmed
	if !run.cleaned {
		return errors.New("cleanupLocalTLS returned nil but not every artifact is confirmed")
	}

	found, err := ops.isTrusted(material.CAFingerprintSHA256)
	if err != nil {
		return fmt.Errorf("IsTrustedSHA256: %w", err)
	}
	if found {
		return errors.New("trust anchor still present after cleanup")
	}
	if err := checkSmokeKeysNotOpenable(ops.open, SmokeCAKeyName, SmokeServerKeyName); err != nil {
		return err
	}
	run.succeeded = true
	return nil
}

// runSmokeLifecycles runs the lifecycle twice to prove repeatability. The
// second cycle starts only after the first one completed: any failure of the
// first, including its postconditions, stops the test.
func runSmokeLifecycles(h smokeHarness, ops smokeLifecycleOps, diagDir string) error {
	if err := runSmokeLifecycle(h, ops, diagDir); err != nil {
		return fmt.Errorf("first lifecycle run failed: %w", err)
	}
	if err := runSmokeLifecycle(h, ops, diagDir); err != nil {
		return fmt.Errorf("second lifecycle run failed: %w", err)
	}
	return nil
}

// checkSmokeKeysNotOpenable is the post-cleanup consistency check. Deletion is
// already confirmed by the successful deletes; this only catches a key that
// still opens or an unexpected open error. ErrKeyNotFound is consistent with
// the confirmed deletion but is not, by itself, proof that the key is absent.
// A key that still opens is closed, never deleted, and a failure to release
// that signer is kept with the result.
func checkSmokeKeysNotOpenable(open func(string) (crypto.Signer, error), names ...string) error {
	for _, name := range names {
		signer, err := open(name)
		if err == nil {
			err := fmt.Errorf("smoke key %q still opens after confirmed deletion", name)
			if cerr := closeSigner(signer); cerr != nil {
				err = errors.Join(err, fmt.Errorf("close the signer of the reopened smoke key %q: %w: %w", name, errSmokeReleaseUnconfirmed, cerr))
			}
			return err
		}
		if !errors.Is(err, ErrKeyNotFound) {
			return fmt.Errorf("unexpected error opening smoke key %q after cleanup: %w", name, err)
		}
	}
	return nil
}

// ---- elevation probe ownership decision (no machine mutation) ----

func TestProbeKeyOwnershipAbsent(t *testing.T) {
	err := probeKeyOwnership(func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }, "probe")
	if err != nil {
		t.Fatalf("absent key: expected nil, got %v", err)
	}
}

func TestProbeKeyOwnershipUnexpectedlyPresent(t *testing.T) {
	signer := newFakeCloseSigner()
	err := probeKeyOwnership(func(string) (crypto.Signer, error) { return signer, nil }, "probe")
	if err == nil {
		t.Fatal("expected error for unexpectedly present key")
	}
	if !signer.closed {
		t.Fatal("present key signer must be closed")
	}

	closeCause := errors.New("release handle failed")
	failing := newFakeCloseSigner()
	failing.closeErr = closeCause
	err = probeKeyOwnership(func(string) (crypto.Signer, error) { return failing, nil }, "probe")
	if err == nil || !errors.Is(err, closeCause) || failing.closeAttempts != 1 {
		t.Fatalf("present key with failing close: err = %v, attempts = %d; want the close cause kept and one attempt", err, failing.closeAttempts)
	}
}

func TestProbeKeyOwnershipUnexpectedOpenError(t *testing.T) {
	sentinel := errors.New("access denied")
	err := probeKeyOwnership(func(string) (crypto.Signer, error) { return nil, sentinel }, "probe")
	if err == nil {
		t.Fatal("expected unexpected open error to be returned")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("returned error does not wrap the sentinel: %v", err)
	}
}

func TestUniqueSmokeProbeName(t *testing.T) {
	a, err := uniqueSmokeProbeName()
	if err != nil {
		t.Fatalf("uniqueSmokeProbeName: %v", err)
	}
	if !strings.HasPrefix(a, identity.SmokeKeyNamespace) {
		t.Fatalf("probe name %q must start with %q", a, identity.SmokeKeyNamespace)
	}
	b, err := uniqueSmokeProbeName()
	if err != nil {
		t.Fatalf("uniqueSmokeProbeName: %v", err)
	}
	if a == b {
		t.Fatal("two unique probe names must differ")
	}
}

// TestIsElevationUnavailable proves the prerequisite-vs-operational classifier
// recognizes only explicit access-denied conditions, so operational failures
// (such as a key-deletion or signer-close error) are never converted into a
// skip. Non-mutating.
func TestIsElevationUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"nte_perm", errors.New("NCryptFinalizeKey: hr=0x80090010"), true},
		{"status_access_denied", errors.New("access denied 0x801f0005"), true},
		{"access_is_denied", errors.New("Access is denied"), true},
		{"provider_missing", errors.New("NCryptOpenStorageProvider: hr=0x80090011"), false},
		{"key_not_found", ErrKeyNotFound, false},
		{"close_failure", errors.New("close elevation probe key: handle closed"), false},
		{"delete_failure", errors.New("delete elevation probe key: key in use"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isElevationUnavailable(tc.err); got != tc.want {
				t.Fatalf("isElevationUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ---- elevation probe SKIP/FAIL classification (offline fakes, no machine key) ----

// fakeElevationKeys records the key operations establishSmokeElevationWith
// performs and returns configured results.
type fakeElevationKeys struct {
	nameErr   error
	openErr   error
	openKey   *fakeCloseSigner
	createErr error
	created   *fakeCloseSigner
	delErrs   []error // result of each successive delete; nil once exhausted
	opens     []string
	creates   []string
	deletes   []string
}

func (f *fakeElevationKeys) deps() smokeElevationDeps {
	return smokeElevationDeps{
		name: func() (string, error) {
			if f.nameErr != nil {
				return "", f.nameErr
			}
			return identity.SmokeKeyNamespace + "elevation-probe-offline", nil
		},
		open: func(name string) (crypto.Signer, error) {
			f.opens = append(f.opens, name)
			if f.openKey != nil {
				return f.openKey, nil
			}
			if f.openErr != nil {
				return nil, f.openErr
			}
			return nil, fmt.Errorf("%w: key %q: hr=0x80090016", ErrKeyNotFound, name)
		},
		create: func(name string) (crypto.Signer, error) {
			f.creates = append(f.creates, name)
			if f.createErr != nil {
				return nil, f.createErr
			}
			f.created = newFakeCloseSigner()
			return f.created, nil
		},
		del: func(name string) error {
			f.deletes = append(f.deletes, name)
			if i := len(f.deletes) - 1; i < len(f.delErrs) {
				return f.delErrs[i]
			}
			return nil
		},
	}
}

// TestEstablishSmokeElevationClassification proves the probe contract offline: a
// denied create is the only SKIP, every failure after the probe key was
// created is an operational FAIL, a delete reporting ErrKeyNotFound is an
// unconfirmed deletion (never success, never SKIP), and success requires a
// confirmed delete of exactly the created key.
func TestEstablishSmokeElevationClassification(t *testing.T) {
	notFound := fmt.Errorf("%w: key %q: hr=0x80090016", ErrKeyNotFound, "probe")
	accessDenied := errors.New("NCryptFinalizeKey: hr=0x80090010")
	closeErr := errors.New("handle close failed")
	inUse := errors.New("key in use")

	cases := []struct {
		name            string
		keys            *fakeElevationKeys
		wantUnavailable bool
		wantErr         []error // each must match; empty means success
		wantCreates     int
		wantDeletes     int
	}{
		{"confirmed delete succeeds", &fakeElevationKeys{}, false, nil, 1, 1},
		{"name generation fails", &fakeElevationKeys{nameErr: errors.New("rng")}, false, []error{}, 0, 0},
		{"preflight opens a key", &fakeElevationKeys{openKey: newFakeCloseSigner()}, false, []error{}, 0, 0},
		{"preflight unexpected error", &fakeElevationKeys{openErr: inUse}, false, []error{inUse}, 0, 0},
		{"create denied is the prerequisite", &fakeElevationKeys{createErr: accessDenied}, true, []error{accessDenied}, 1, 0},
		{"create other error", &fakeElevationKeys{createErr: inUse}, false, []error{inUse}, 1, 0},
		{"delete not found is unconfirmed", &fakeElevationKeys{delErrs: []error{notFound}}, false, []error{ErrKeyDeletionUnconfirmed, ErrKeyNotFound}, 1, 1},
		{"delete access denied is operational", &fakeElevationKeys{delErrs: []error{accessDenied}}, false, []error{accessDenied}, 1, 1},
		{"delete other error", &fakeElevationKeys{delErrs: []error{inUse}}, false, []error{inUse}, 1, 1},
		{"close fails, key not deleted", &fakeElevationKeys{}, false, []error{closeErr, errSmokeReleaseUnconfirmed}, 1, 0},
		{"close fails, key not deleted even if delete would fail", &fakeElevationKeys{delErrs: []error{notFound}}, false, []error{closeErr, errSmokeReleaseUnconfirmed}, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.keys.deps()
			if strings.HasPrefix(tc.name, "close fails") {
				create := deps.create
				deps.create = func(name string) (crypto.Signer, error) {
					s, err := create(name)
					tc.keys.created.closeErr = closeErr
					return s, err
				}
			}

			unavailable, err := establishSmokeElevationWith(deps)
			if unavailable != tc.wantUnavailable {
				t.Fatalf("unavailable = %v, want %v (err %v)", unavailable, tc.wantUnavailable, err)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatal("err = nil, want a failure")
				}
				for _, want := range tc.wantErr {
					if !errors.Is(err, want) {
						t.Fatalf("err = %v, want it to match %v", err, want)
					}
				}
			}
			if len(tc.keys.creates) != tc.wantCreates || len(tc.keys.deletes) != tc.wantDeletes {
				t.Fatalf("creates=%d deletes=%d, want %d/%d", len(tc.keys.creates), len(tc.keys.deletes), tc.wantCreates, tc.wantDeletes)
			}
			for _, d := range tc.keys.deletes {
				if len(tc.keys.creates) != 1 || d != tc.keys.creates[0] {
					t.Fatalf("deleted %q, which is not the key this call created (%v)", d, tc.keys.creates)
				}
			}
			if tc.keys.created != nil && tc.keys.created.closeAttempts != 1 {
				t.Fatalf("the created probe signer was closed %d times, want exactly 1", tc.keys.created.closeAttempts)
			}
			if strings.HasPrefix(tc.name, "close fails") && !strings.Contains(err.Error(), tc.keys.creates[0]) {
				t.Fatalf("err = %v, want it to name the exact probe key %q left in place", err, tc.keys.creates[0])
			}
			if tc.keys.openKey != nil && !tc.keys.openKey.closed {
				t.Fatal("a key opened by the preflight must be closed and left in place")
			}
		})
	}
}

// TestEstablishSmokeElevationCreateCleanupFailed proves that a create error
// reporting a failed CNG cleanup (windowscng.ErrCleanupFailed: the key created
// by the failed call may persist) is an operational FAIL even when
// access-denied text appears in the original failure or only in the cleanup
// part, including after mapCNGError has flattened the chain to text. The
// original causes and the exact probe name are kept, and nothing is deleted.
// An ordinary denied create without a cleanup failure stays the SKIP
// prerequisite.
func TestEstablishSmokeElevationCreateCleanupFailed(t *testing.T) {
	accessDenied := errors.New("NCryptFinalizeKey: hr=0x80090010")
	cleanupDenied := fmt.Errorf("%w: NCryptDeleteKey: hr=0x80090010", windowscng.ErrCleanupFailed)
	validationErr := errors.New("created key failed post-creation validation")
	flattened := mapCNGError(errors.Join(
		fmt.Errorf("%w: reopen created key", windowscng.ErrKeyNotFound),
		fmt.Errorf("%w: access denied", windowscng.ErrCleanupFailed),
	))
	if errors.Is(flattened, windowscng.ErrCleanupFailed) {
		t.Fatal("fixture: mapCNGError was expected to flatten this chain to text")
	}

	cases := []struct {
		name            string
		createErr       error
		wantUnavailable bool
		wantIs          []error
	}{
		{"denied create with failed cleanup", errors.Join(accessDenied, fmt.Errorf("%w: delete failed", windowscng.ErrCleanupFailed)),
			false, []error{accessDenied, windowscng.ErrCleanupFailed}},
		{"denial only in the cleanup part", errors.Join(validationErr, cleanupDenied),
			false, []error{validationErr, windowscng.ErrCleanupFailed}},
		{"failed cleanup flattened by mapCNGError", flattened,
			false, []error{ErrKeyNotFound}},
		{"ordinary denied create", accessDenied,
			true, []error{accessDenied}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := &fakeElevationKeys{createErr: tc.createErr}
			unavailable, err := establishSmokeElevationWith(keys.deps())
			if unavailable != tc.wantUnavailable {
				t.Fatalf("unavailable = %v, want %v (err %v)", unavailable, tc.wantUnavailable, err)
			}
			for _, want := range tc.wantIs {
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want the original cause %v kept", err, want)
				}
			}
			if !tc.wantUnavailable {
				if len(keys.creates) != 1 || !strings.Contains(err.Error(), keys.creates[0]) {
					t.Fatalf("err = %v, want it to name the exact probe key %v", err, keys.creates)
				}
			}
			if len(keys.opens) != 1 || len(keys.creates) != 1 || len(keys.deletes) != 0 {
				t.Fatalf("opens=%d creates=%d deletes=%d, want 1/1/0 (no key deleted on this path)", len(keys.opens), len(keys.creates), len(keys.deletes))
			}
		})
	}
}

// TestCheckSmokeKeysNotOpenable proves the post-cleanup check fails on a key
// that still opens (closing it) or on an unexpected open error, and accepts
// ErrKeyNotFound only as consistent with an already-confirmed deletion.
func TestCheckSmokeKeysNotOpenable(t *testing.T) {
	notFound := func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }
	if err := checkSmokeKeysNotOpenable(notFound, "a", "b"); err != nil {
		t.Fatalf("not found after confirmed deletion: %v", err)
	}

	signer := newFakeCloseSigner()
	err := checkSmokeKeysNotOpenable(func(string) (crypto.Signer, error) { return signer, nil }, "a")
	if err == nil || !signer.closed {
		t.Fatalf("still-opening key: err = %v, closed = %v; want error and closed signer", err, signer.closed)
	}

	closeCause := errors.New("release handle failed")
	failing := newFakeCloseSigner()
	failing.closeErr = closeCause
	err = checkSmokeKeysNotOpenable(func(string) (crypto.Signer, error) { return failing, nil }, "a")
	if err == nil || !errors.Is(err, closeCause) || !errors.Is(err, errSmokeReleaseUnconfirmed) || failing.closeAttempts != 1 {
		t.Fatalf("still-opening key with failing close: err = %v, attempts = %d; want the close cause kept and one attempt", err, failing.closeAttempts)
	}

	inUse := errors.New("key in use")
	if err := checkSmokeKeysNotOpenable(func(string) (crypto.Signer, error) { return nil, inUse }, "a"); !errors.Is(err, inUse) {
		t.Fatalf("unexpected open error: err = %v, want it wrapped", err)
	}
}

// ---- smoke lifecycle coordinator (offline fakes, no machine mutation) ----

// smokeFakeMachine models the machine state a smoke lifecycle run touches and
// records every operation, in order, in one event log. Its key deletion flags
// a violation whenever the serving signer of the last provisioning has not
// been released successfully; a failed Close never counts as a release.
type smokeFakeMachine struct {
	events     []string
	violations []string
	provisions int

	keys        map[string]bool
	trusted     map[[32]byte]bool
	preexisting map[string]*fakeCloseSigner // keys that open before the run
	signers     []*smokeFakeSigner          // serving signers, one per Material returned

	provisionEarlyErr error // returned before any artifact exists
	provisionLateErr  error // returned after keys, CA DER and trust anchor exist
	derAsDirectory    bool  // the persisted CA DER path is unreadable
	lockStateDir      bool  // a file held open in the state directory makes its removal fail
	cleanup           func(func())
	closeErr          error
	closeErrFromCycle int // closeErr applies from this cycle on (0 or 1: every cycle)
	verifyState       TrustState
	trustErr          error
	delErr            map[string]error
	stillTrusted      bool // the post-cleanup trust check reports the anchor
}

func newSmokeFakeMachine() *smokeFakeMachine {
	return &smokeFakeMachine{
		keys:        map[string]bool{},
		trusted:     map[[32]byte]bool{},
		preexisting: map[string]*fakeCloseSigner{},
		delErr:      map[string]error{},
		verifyState: TrustHealthy,
	}
}

func (m *smokeFakeMachine) log(event string) { m.events = append(m.events, event) }

// count returns how many events equal event.
func (m *smokeFakeMachine) count(event string) int {
	n := 0
	for _, e := range m.events {
		if e == event {
			n++
		}
	}
	return n
}

// countPrefix returns how many events start with prefix.
func (m *smokeFakeMachine) countPrefix(prefix string) int {
	n := 0
	for _, e := range m.events {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// smokeFakeSigner is a serving signer that records every Close attempt and its
// result in the machine log.
type smokeFakeSigner struct {
	*fakeCloseSigner
	m        *smokeFakeMachine
	cycle    int
	attempts int
	released bool
}

func (s *smokeFakeSigner) Close() error {
	s.attempts++
	if s.m.closeErr != nil && s.cycle >= s.m.closeErrFromCycle {
		s.m.log("close:failed")
		return s.m.closeErr
	}
	s.released = true
	s.m.log("close:ok")
	return nil
}

func (m *smokeFakeMachine) ops() smokeLifecycleOps {
	return smokeLifecycleOps{
		open: func(name string) (crypto.Signer, error) {
			m.log("open:" + name)
			if s, ok := m.preexisting[name]; ok {
				return s, nil
			}
			if m.keys[name] {
				return newFakeCloseSigner(), nil
			}
			return nil, fmt.Errorf("%w: key %q", ErrKeyNotFound, name)
		},
		provision: func(root string) (Material, error) {
			m.provisions++
			m.log("provision")
			if m.provisionEarlyErr != nil {
				return Material{}, m.provisionEarlyErr
			}
			der := []byte(fmt.Sprintf("fake-ca-der-%d", m.provisions))
			m.keys[SmokeCAKeyName], m.keys[SmokeServerKeyName] = true, true
			tlsDir := filepath.Join(root, tlsSubDir)
			derPath := filepath.Join(tlsDir, caCertFile)
			if m.derAsDirectory {
				if err := os.MkdirAll(derPath, 0o700); err != nil {
					return Material{}, err
				}
			} else {
				if err := os.MkdirAll(tlsDir, 0o700); err != nil {
					return Material{}, err
				}
				if err := os.WriteFile(derPath, der, 0o600); err != nil {
					return Material{}, err
				}
			}
			if m.lockStateDir {
				// Windows refuses to delete a file opened without
				// FILE_SHARE_DELETE, so removing the state directory
				// fails. The handle is closed by a cleanup registered
				// after the run's fallback, which therefore runs first,
				// before the fallback and the t.TempDir removal.
				f, err := os.Create(filepath.Join(tlsDir, "held-open"))
				if err != nil {
					return Material{}, err
				}
				m.cleanup(func() { f.Close() })
			}
			m.trusted[sha256.Sum256(der)] = true
			if m.provisionLateErr != nil {
				return Material{}, m.provisionLateErr
			}
			s := &smokeFakeSigner{fakeCloseSigner: newFakeCloseSigner(), m: m, cycle: m.provisions}
			m.signers = append(m.signers, s)
			return Material{
				Certificate:         tls.Certificate{PrivateKey: s},
				CACertificate:       &x509.Certificate{Raw: der},
				CAFingerprintSHA256: sha256.Sum256(der),
			}, nil
		},
		verifyTrust: func([]byte) (TrustState, error) {
			m.log("verify")
			return m.verifyState, nil
		},
		removeTrust: func(der []byte) error {
			m.log("trust:remove")
			if m.trustErr != nil {
				return m.trustErr
			}
			fp := sha256.Sum256(der)
			if !m.trusted[fp] {
				return ErrTrustAnchorNotFound
			}
			delete(m.trusted, fp)
			return nil
		},
		isTrusted: func(fp [32]byte) (bool, error) {
			m.log("trust:check")
			return m.stillTrusted || m.trusted[fp], nil
		},
		del: func(name string) error {
			m.log("del:" + name)
			if n := len(m.signers); n > 0 && !m.signers[n-1].released {
				m.violations = append(m.violations, fmt.Sprintf("key %q deleted while the serving signer was not released", name))
			}
			if err := m.delErr[name]; err != nil {
				return err
			}
			if !m.keys[name] {
				return fmt.Errorf("%w: key %q", ErrKeyNotFound, name)
			}
			delete(m.keys, name)
			return nil
		},
	}
}

// smokeTestHarness wraps a real subtest, so TempDir and Cleanup keep their real
// last-in, first-out ordering, and captures what the run reports.
type smokeTestHarness struct {
	*testing.T
	logs   []string
	errors []error
}

func (h *smokeTestHarness) Logf(format string, args ...any) {
	h.logs = append(h.logs, fmt.Sprintf(format, args...))
}

func (h *smokeTestHarness) Errorf(format string, args ...any) {
	for _, a := range args {
		if err, ok := a.(error); ok {
			h.errors = append(h.errors, err)
			return
		}
	}
	h.errors = append(h.errors, fmt.Errorf(format, args...))
}

// smokeScenario runs runSmokeLifecycles on the fake machine inside a subtest
// and returns once that subtest's cleanups (fallbacks, then the t.TempDir
// removal) have run. It returns the harness, the diagnostics directory, which
// outlives the subtest, and the run error.
func smokeScenario(t *testing.T, m *smokeFakeMachine) (*smokeTestHarness, string, error) {
	t.Helper()
	diagDir := t.TempDir()
	h, err := smokeScenarioIn(t, m, diagDir)
	return h, diagDir, err
}

// smokeScenarioIn is smokeScenario with an explicit diagnostics directory.
func smokeScenarioIn(t *testing.T, m *smokeFakeMachine, diagDir string) (*smokeTestHarness, error) {
	t.Helper()
	var runErr error
	var h *smokeTestHarness
	t.Run("run", func(st *testing.T) {
		h = &smokeTestHarness{T: st}
		m.cleanup = st.Cleanup
		runErr = runSmokeLifecycles(h, m.ops(), diagDir)
	})
	return h, runErr
}

// smokeDiagFiles returns the diagnostics written to diagDir, by suffix.
func smokeDiagFiles(t *testing.T, diagDir string) (reports []string, ders [][]byte) {
	t.Helper()
	entries, err := os.ReadDir(diagDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(diagDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.HasSuffix(e.Name(), "-ca.der"):
			ders = append(ders, data)
		case strings.HasSuffix(e.Name(), ".txt"):
			reports = append(reports, string(data))
		}
	}
	return reports, ders
}

func joinedErrors(errs []error) error { return errors.Join(errs...) }

func requireNoViolations(t *testing.T, m *smokeFakeMachine) {
	t.Helper()
	if len(m.violations) != 0 {
		t.Fatalf("violations: %v (events %v)", m.violations, m.events)
	}
}

// TestSmokeLifecycleTwoCyclesOrder proves the coordinator's order on success:
// ownership preflight, provisioning, trust verification, a successful release
// of the serving signer, then trust removal and both key deletions, then the
// post-cleanup checks, for each of the two cycles. The second cycle runs only
// after the first completed, and the fallback of the first cycle does not touch
// the artifacts of the second.
func TestSmokeLifecycleTwoCyclesOrder(t *testing.T) {
	m := newSmokeFakeMachine()
	h, diagDir, err := smokeScenario(t, m)
	if err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	if len(h.errors) != 0 {
		t.Fatalf("fallback reported %v on a successful run", h.errors)
	}
	requireNoViolations(t, m)

	cycle := []string{
		"open:" + SmokeCAKeyName, "open:" + SmokeServerKeyName,
		"provision", "verify", "close:ok",
		"trust:remove", "del:" + SmokeCAKeyName, "del:" + SmokeServerKeyName,
		"trust:check", "open:" + SmokeCAKeyName, "open:" + SmokeServerKeyName,
	}
	want := strings.Join(append(append([]string{}, cycle...), cycle...), ",")
	if got := strings.Join(m.events, ","); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
	for i, s := range m.signers {
		if s.attempts != 1 {
			t.Fatalf("serving signer %d closed %d times, want 1", i, s.attempts)
		}
	}
	if reports, _ := smokeDiagFiles(t, diagDir); len(reports) != 0 {
		t.Fatalf("diagnostics written for a successful run: %v", reports)
	}
}

// TestSmokeLifecycleCloseFailureDeletesNoKey proves the no-deletion policy when the
// release of the serving signer fails, either in the main path or in the
// fallback itself (the main path failed before releasing): Close is attempted
// once, no key is deleted, the trust anchor of the exact CA DER is removed at
// most once, the close cause stays matchable, the second cycle does not start,
// and the diagnostics outside the temporary directory name the keys and the CA
// identity.
func TestSmokeLifecycleCloseFailureDeletesNoKey(t *testing.T) {
	closeCause := errors.New("release handle failed")
	trustFailure := errors.New("remove anchor failed")
	cases := []struct {
		name          string
		verifyState   TrustState
		trustErr      error
		wantTrustNote string
	}{
		{"main path, trust removed", TrustHealthy, nil, "trust anchor: confirmed\n"},
		{"main path, trust already absent", TrustHealthy, ErrTrustAnchorNotFound, "trust anchor: confirmed (already absent)"},
		{"main path, trust removal fails", TrustHealthy, trustFailure, "trust anchor: FAILED"},
		{"fallback close after an earlier failure", TrustConflict, nil, "trust anchor: confirmed\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSmokeFakeMachine()
			m.closeErr = closeCause
			m.verifyState = tc.verifyState
			m.trustErr = tc.trustErr

			h, diagDir, err := smokeScenario(t, m)
			if err == nil {
				t.Fatal("lifecycle succeeded, want a failure")
			}
			if tc.verifyState == TrustHealthy && (!errors.Is(err, closeCause) || !errors.Is(err, errSmokeReleaseUnconfirmed)) {
				t.Fatalf("err = %v, want the close cause and errSmokeReleaseUnconfirmed", err)
			}
			requireNoViolations(t, m)
			if n := m.countPrefix("del:"); n != 0 {
				t.Fatalf("%d key deletions after a failed release (events %v)", n, m.events)
			}
			if n := m.count("trust:remove"); n != 1 {
				t.Fatalf("trust removals = %d, want exactly 1 (events %v)", n, m.events)
			}
			if m.provisions != 1 || m.countPrefix("open:") != 2 {
				t.Fatalf("provisions = %d, opens = %d, want 1 and only the first preflight: the second cycle must not start", m.provisions, m.countPrefix("open:"))
			}
			if len(m.signers) != 1 || m.signers[0].attempts != 1 {
				t.Fatalf("serving signer close attempts = %d, want 1", m.signers[0].attempts)
			}

			reported := joinedErrors(h.errors)
			if !errors.Is(reported, closeCause) || !errors.Is(reported, errSmokeReleaseUnconfirmed) {
				t.Fatalf("fallback reported %v, want the close cause kept", reported)
			}
			for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
				if !strings.Contains(reported.Error(), name) {
					t.Fatalf("fallback report %v does not name key %q", reported, name)
				}
			}
			if errors.Is(reported, ErrKeyDeletionUnconfirmed) {
				t.Fatalf("keys not deleted by policy reported as unconfirmed deletions: %v", reported)
			}
			if (tc.trustErr == trustFailure) != errors.Is(reported, trustFailure) {
				t.Fatalf("trust failure reporting: %v", reported)
			}

			reports, ders := smokeDiagFiles(t, diagDir)
			if len(reports) != 1 || len(ders) != 1 || string(ders[0]) != "fake-ca-der-1" {
				t.Fatalf("diagnostics: %d reports, DERs %q; want one report and the exact CA DER", len(reports), ders)
			}
			fp := fmt.Sprintf("%x", sha256.Sum256(ders[0]))
			for _, want := range []string{"release not confirmed", fp, SmokeCAKeyName + ": NOT ATTEMPTED by policy", SmokeServerKeyName + ": NOT ATTEMPTED by policy", tc.wantTrustNote} {
				if !strings.Contains(reports[0], want) {
					t.Fatalf("diagnostics missing %q:\n%s", want, reports[0])
				}
			}
		})
	}
}

// TestSmokeLifecycleFallbackAfterPartialProvisioning proves that the fallback
// is registered before provisioning and runs before the t.TempDir removal: a
// provisioning failure after keys, CA DER and trust anchor exist (and no
// Material is returned) is cleaned up from the persisted CA DER. Without a CA
// DER no trust removal is attempted; an unreadable DER leaves the identity
// unrecovered and the anchor untouched.
func TestSmokeLifecycleFallbackAfterPartialProvisioning(t *testing.T) {
	provisionFailure := errors.New("install trust failed late")

	t.Run("persisted DER", func(t *testing.T) {
		m := newSmokeFakeMachine()
		m.provisionLateErr = provisionFailure
		h, diagDir, err := smokeScenario(t, m)
		if !errors.Is(err, provisionFailure) {
			t.Fatalf("err = %v, want the provisioning failure", err)
		}
		want := "open:" + SmokeCAKeyName + ",open:" + SmokeServerKeyName + ",provision,trust:remove,del:" + SmokeCAKeyName + ",del:" + SmokeServerKeyName
		if got := strings.Join(m.events, ","); got != want {
			t.Fatalf("events\n got %s\nwant %s", got, want)
		}
		if len(m.trusted) != 0 || len(m.keys) != 0 {
			t.Fatalf("left behind: trusted %v, keys %v", m.trusted, m.keys)
		}
		if len(h.errors) != 0 {
			t.Fatalf("fallback reported %v", h.errors)
		}
		if _, ders := smokeDiagFiles(t, diagDir); len(ders) != 1 || string(ders[0]) != "fake-ca-der-1" {
			t.Fatalf("diagnostic DERs %q, want the persisted CA DER", ders)
		}
	})

	t.Run("no artifact", func(t *testing.T) {
		m := newSmokeFakeMachine()
		m.provisionEarlyErr = provisionFailure
		h, diagDir, _ := smokeScenario(t, m)
		if n := m.count("trust:remove"); n != 0 {
			t.Fatalf("trust removal attempted without a CA DER")
		}
		if m.countPrefix("del:") != 2 || !errors.Is(joinedErrors(h.errors), ErrKeyDeletionUnconfirmed) {
			t.Fatalf("events %v, errors %v: want both deletes attempted and reported unconfirmed", m.events, h.errors)
		}
		if reports, _ := smokeDiagFiles(t, diagDir); len(reports) != 1 || !strings.Contains(reports[0], "no CA DER was written") {
			t.Fatalf("diagnostics %v", reports)
		}
	})

	t.Run("unreadable DER", func(t *testing.T) {
		m := newSmokeFakeMachine()
		m.provisionLateErr = provisionFailure
		m.derAsDirectory = true
		h, diagDir, _ := smokeScenario(t, m)
		if n := m.count("trust:remove"); n != 0 {
			t.Fatalf("trust removal attempted with an unrecovered identity")
		}
		if !errors.Is(joinedErrors(h.errors), errSmokeIdentityUnrecovered) {
			t.Fatalf("errors %v, want errSmokeIdentityUnrecovered", h.errors)
		}
		reports, ders := smokeDiagFiles(t, diagDir)
		if len(reports) != 1 || len(ders) != 0 || !strings.Contains(reports[0], "NOT RECOVERED") {
			t.Fatalf("diagnostics %v, DERs %d: want an unrecovered identity and no DER", reports, len(ders))
		}
	})
}

// TestSmokeLifecyclePreflightRefusesExistingKey proves that a smoke key that
// already opens, CA or server, stops the run before provisioning: the key is
// closed once and never deleted, a failure to release it is kept, and the
// refused run registers no cleanup.
func TestSmokeLifecyclePreflightRefusesExistingKey(t *testing.T) {
	closeCause := errors.New("release existing handle failed")
	for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
		for _, closeErr := range []error{nil, closeCause} {
			t.Run(fmt.Sprintf("%s close error %v", name, closeErr != nil), func(t *testing.T) {
				m := newSmokeFakeMachine()
				existing := newFakeCloseSigner()
				existing.closeErr = closeErr
				m.preexisting[name] = existing

				h, diagDir, err := smokeScenario(t, m)
				if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "STOP") {
					t.Fatalf("err = %v, want a STOP naming %q", err, name)
				}
				if strings.Contains(err.Error(), "cleanup first") {
					t.Fatalf("err = %v suggests an automatic cleanup", err)
				}
				if closeErr != nil && !errors.Is(err, closeCause) {
					t.Fatalf("err = %v, want the close cause kept", err)
				}
				if existing.closeAttempts != 1 {
					t.Fatalf("existing key closed %d times, want 1", existing.closeAttempts)
				}
				if m.provisions != 0 || m.countPrefix("del:") != 0 || m.count("trust:remove") != 0 {
					t.Fatalf("refused run acted: events %v", m.events)
				}
				if len(h.errors) != 0 {
					t.Fatalf("refused run registered a cleanup that reported %v", h.errors)
				}
				if reports, _ := smokeDiagFiles(t, diagDir); len(reports) != 0 {
					t.Fatalf("refused run wrote diagnostics %v", reports)
				}
			})
		}
	}
}

// TestSmokeLifecyclePartialCleanup proves that the outcome of every artifact of
// the main cleanup is kept: the fallback never repeats an operation already
// attempted, confirmed removals are not reported, failed ones are, and a key
// deletion reporting ErrKeyNotFound stays unconfirmed.
func TestSmokeLifecyclePartialCleanup(t *testing.T) {
	inUse := errors.New("key in use")
	trustFailure := errors.New("remove anchor failed")
	cases := []struct {
		name       string
		setup      func(*smokeFakeMachine)
		wantIs     []error
		wantNot    string // a key name that must not be reported
		wantDirRet bool
		wantDiag   string // extra text the diagnostics must contain
	}{
		{"server delete fails", func(m *smokeFakeMachine) { m.delErr[SmokeServerKeyName] = inUse }, []error{inUse}, SmokeCAKeyName, true, "key in use"},
		{"trust removal fails", func(m *smokeFakeMachine) { m.trustErr = trustFailure }, []error{trustFailure}, SmokeCAKeyName, false, "remove anchor failed"},
		{"CA delete not found", func(m *smokeFakeMachine) { m.delErr[SmokeCAKeyName] = ErrKeyNotFound }, []error{ErrKeyDeletionUnconfirmed}, SmokeServerKeyName, true, "key deletion unconfirmed"},
		{"state directory removal fails", func(m *smokeFakeMachine) { m.lockStateDir = true }, nil, SmokeCAKeyName, true, "main cleanup error: remove TLS state directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newSmokeFakeMachine()
			tc.setup(m)
			h, diagDir, err := smokeScenario(t, m)
			if err == nil {
				t.Fatal("lifecycle succeeded, want a cleanup failure")
			}
			requireNoViolations(t, m)
			for _, ev := range []string{"trust:remove", "del:" + SmokeCAKeyName, "del:" + SmokeServerKeyName} {
				if n := m.count(ev); n != 1 {
					t.Fatalf("%s happened %d times, want exactly 1 (events %v)", ev, n, m.events)
				}
			}
			if m.provisions != 1 || m.countPrefix("open:") != 2 {
				t.Fatalf("provisions = %d, opens = %d, want 1 and only the first preflight (events %v)", m.provisions, m.countPrefix("open:"), m.events)
			}
			reported := joinedErrors(h.errors)
			if reported == nil {
				t.Fatal("fallback reported nothing, want the unresolved artifacts")
			}
			for _, want := range tc.wantIs {
				if !errors.Is(reported, want) {
					t.Fatalf("fallback reported %v, want it to match %v", reported, want)
				}
			}
			if strings.Contains(reported.Error(), "delete smoke key \""+tc.wantNot) {
				t.Fatalf("confirmed deletion of %q reported as unresolved: %v", tc.wantNot, reported)
			}
			if got := strings.Contains(reported.Error(), "still present after cleanup"); got != tc.wantDirRet {
				t.Fatalf("state directory still present reported = %v, want %v: %v", got, tc.wantDirRet, reported)
			}
			reports, ders := smokeDiagFiles(t, diagDir)
			if len(reports) != 1 || len(ders) != 1 {
				t.Fatalf("diagnostics: %d reports, %d DERs, want 1/1", len(reports), len(ders))
			}
			if !strings.Contains(reports[0], "key "+tc.wantNot+": confirmed") {
				t.Fatalf("diagnostics do not keep the confirmed deletion of %q:\n%s", tc.wantNot, reports[0])
			}
			if !strings.Contains(reports[0], tc.wantDiag) {
				t.Fatalf("diagnostics missing %q:\n%s", tc.wantDiag, reports[0])
			}
		})
	}
}

// TestSmokeLifecycleSecondCycleFailure proves that a failure of the second
// cycle, after a completed first one, is handled by the second cycle's
// fallback only: the first cycle's fallback stays inert, no key of either
// cycle is deleted after the failed release, and the diagnostics carry the
// second cycle's CA identity.
func TestSmokeLifecycleSecondCycleFailure(t *testing.T) {
	closeCause := errors.New("release handle failed")
	m := newSmokeFakeMachine()
	m.closeErr = closeCause
	m.closeErrFromCycle = 2
	h, diagDir, err := smokeScenario(t, m)
	if err == nil || !strings.Contains(err.Error(), "second lifecycle run failed") || !errors.Is(err, closeCause) {
		t.Fatalf("err = %v, want the second cycle to fail on the close", err)
	}
	requireNoViolations(t, m)
	cycle1 := []string{
		"open:" + SmokeCAKeyName, "open:" + SmokeServerKeyName,
		"provision", "verify", "close:ok",
		"trust:remove", "del:" + SmokeCAKeyName, "del:" + SmokeServerKeyName,
		"trust:check", "open:" + SmokeCAKeyName, "open:" + SmokeServerKeyName,
	}
	cycle2 := []string{
		"open:" + SmokeCAKeyName, "open:" + SmokeServerKeyName,
		"provision", "verify", "close:failed",
		"trust:remove",
	}
	want := strings.Join(append(cycle1, cycle2...), ",")
	if got := strings.Join(m.events, ","); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
	if !errors.Is(joinedErrors(h.errors), closeCause) {
		t.Fatalf("fallback reported %v, want the close cause", h.errors)
	}
	reports, ders := smokeDiagFiles(t, diagDir)
	if len(reports) != 1 || len(ders) != 1 || string(ders[0]) != "fake-ca-der-2" {
		t.Fatalf("diagnostics: %d reports, DERs %q; want one report for the second cycle", len(reports), ders)
	}
}

// TestSmokeFallbackRepeatedCallIsInert proves that calling the fallback again
// on the same run performs no machine operation and no new Close attempt, and
// still reports the same unresolved artifacts.
func TestSmokeFallbackRepeatedCallIsInert(t *testing.T) {
	closeCause := errors.New("release handle failed")
	m := newSmokeFakeMachine()
	m.closeErr = closeCause
	ops := m.ops()
	root := t.TempDir()
	material, err := ops.provision(root)
	if err != nil {
		t.Fatal(err)
	}
	h := &smokeTestHarness{T: t}
	run := &smokeRun{tlsDir: filepath.Join(root, tlsSubDir), ops: ops, h: h, material: &material, caDER: material.CACertificate.Raw}

	first := run.fallback()
	events := len(m.events)
	second := run.fallback()
	if len(m.events) != events {
		t.Fatalf("second fallback acted: %v", m.events[events:])
	}
	if m.signers[0].attempts != 1 || m.countPrefix("del:") != 0 || m.count("trust:remove") != 1 {
		t.Fatalf("attempts = %d, events %v: want one Close, no delete, one trust removal", m.signers[0].attempts, m.events)
	}
	if len(first) == 0 || len(first) != len(second) || !errors.Is(joinedErrors(second), closeCause) {
		t.Fatalf("first %v, second %v: want the same unresolved artifacts, close cause kept", first, second)
	}
	if err := run.closeMaterial(); !errors.Is(err, closeCause) {
		t.Fatalf("closeMaterial after a failed release = %v, want the persistent close error", err)
	}
}

// TestSmokeFallbackReportsDiagnosticsWriteFailure proves that a diagnostics
// directory that cannot be written is reported, not ignored.
func TestSmokeFallbackReportsDiagnosticsWriteFailure(t *testing.T) {
	m := newSmokeFakeMachine()
	m.provisionLateErr = errors.New("install trust failed late")
	h, _ := smokeScenarioIn(t, m, filepath.Join(t.TempDir(), "missing"))
	reported := joinedErrors(h.errors)
	if reported == nil || !strings.Contains(reported.Error(), "write smoke diagnostics") || !strings.Contains(reported.Error(), "write smoke CA DER") {
		t.Fatalf("fallback reported %v, want both diagnostics write failures", reported)
	}
}

// TestSmokeLifecycleFirstCycleFailureStopsSecond proves that a postcondition
// failure of the first cycle, after a confirmed cleanup, stops the test before
// the second cycle and triggers no further deletion.
func TestSmokeLifecycleFirstCycleFailureStopsSecond(t *testing.T) {
	m := newSmokeFakeMachine()
	m.stillTrusted = true
	h, diagDir, err := smokeScenario(t, m)
	if err == nil || !strings.Contains(err.Error(), "first lifecycle run failed") {
		t.Fatalf("err = %v, want the first cycle to fail", err)
	}
	if m.provisions != 1 || m.countPrefix("del:") != 2 || m.count("trust:remove") != 1 || m.countPrefix("open:") != 2 {
		t.Fatalf("events %v: want one cycle and no repeated cleanup", m.events)
	}
	if len(h.errors) != 0 {
		t.Fatalf("fallback reported %v after a confirmed cleanup", h.errors)
	}
	if reports, _ := smokeDiagFiles(t, diagDir); len(reports) != 1 {
		t.Fatalf("diagnostics %v, want one report", reports)
	}
}

// TestSmokeOwnershipPreflight covers the preflight helper directly.
func TestSmokeOwnershipPreflight(t *testing.T) {
	if err := smokeOwnershipPreflight(func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }, SmokeCAKeyName, SmokeServerKeyName); err != nil {
		t.Fatalf("absent keys: %v", err)
	}

	signer := newFakeCloseSigner()
	err := smokeOwnershipPreflight(func(name string) (crypto.Signer, error) {
		if name == SmokeServerKeyName {
			return signer, nil
		}
		return nil, ErrKeyNotFound
	}, SmokeCAKeyName, SmokeServerKeyName)
	if err == nil || !strings.Contains(err.Error(), SmokeServerKeyName) {
		t.Fatalf("existing server key: err = %v, want a failure naming it", err)
	}
	if signer.closeAttempts != 1 {
		t.Fatalf("existing key signer closed %d times, want 1", signer.closeAttempts)
	}

	openErr := errors.New("access denied")
	if err := smokeOwnershipPreflight(func(string) (crypto.Signer, error) { return nil, openErr }, SmokeCAKeyName); !errors.Is(err, openErr) {
		t.Fatalf("unexpected open error: err = %v, want it wrapped", err)
	}
}
