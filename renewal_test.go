package localtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var harnessIssued = time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

// trackedOpener models an open-only key opener. Every open returns a new
// closable handle over the same key so tests can prove each handle's release.
type trackedOpener struct {
	key    *ecdsa.PrivateKey
	opened []*fakeCloseSigner
	err    error
}

func (o *trackedOpener) open() (crypto.Signer, error) {
	if o.err != nil {
		return nil, o.err
	}
	s := &fakeCloseSigner{key: o.key}
	o.opened = append(o.opened, s)
	return s, nil
}

func (o *trackedOpener) unclosed() int {
	n := 0
	for _, s := range o.opened {
		if !s.closed {
			n++
		}
	}
	return n
}

// stateTrust is a read-only TrustVerifier with a settable state.
type stateTrust struct {
	state TrustState
	err   error
	calls int
}

func (s *stateTrust) VerifyTrust([]byte) (TrustState, error) {
	s.calls++
	return s.state, s.err
}
func (s *stateTrust) IsTrustedSHA256([32]byte) (bool, error) { return s.state == TrustHealthy, s.err }

type renewalHarness struct {
	t        *testing.T
	dir      string
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	leaf     *x509.Certificate
	caOpen   *trackedOpener
	srvOpen  *trackedOpener
	trust    *stateTrust
	now      time.Time
	fs       fileSystem
	tempMade int
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newRenewalHarness persists a CA and a server certificate issued at issued,
// both from in-memory keys, and models open-only key access.
func newRenewalHarness(t *testing.T, issued time.Time) *renewalHarness {
	t.Helper()
	caKey, srvKey := mustKey(t), mustKey(t)
	ca, err := generateCAWithSigner(issued, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := generateServerCertWithSigner(issued, ca, caKey, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	h := &renewalHarness{
		t:       t,
		dir:     t.TempDir(),
		caKey:   caKey,
		caCert:  ca,
		leaf:    leaf,
		caOpen:  &trackedOpener{key: caKey},
		srvOpen: &trackedOpener{key: srvKey},
		trust:   &stateTrust{state: TrustHealthy},
		now:     issued,
		fs:      osFS,
	}
	base := h.fs.createTemp
	h.fs.createTemp = func(dir, pattern string) (tempFile, error) {
		h.tempMade++
		return base(dir, pattern)
	}
	h.write(caCertFile, ca.Raw)
	h.write(serverCertFile, leaf.Raw)
	return h
}

func (h *renewalHarness) env() machineEnv {
	return machineEnv{
		tlsDir:        h.dir,
		openCAKey:     h.caOpen.open,
		openServerKey: h.srvOpen.open,
		trust:         h.trust,
		now:           func() time.Time { return h.now },
		fs:            h.fs,
	}
}

func (h *renewalHarness) write(name string, data []byte) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), data, 0600); err != nil {
		h.t.Fatal(err)
	}
}

// read returns the file's bytes, or nil when it does not exist.
func (h *renewalHarness) read(name string) []byte {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

func (h *renewalHarness) assertSignersReleased() {
	h.t.Helper()
	if n := h.caOpen.unclosed() + h.srvOpen.unclosed(); n != 0 {
		h.t.Fatalf("%d opened signer(s) were not released", n)
	}
}

func (h *renewalHarness) assertNoTemps() {
	h.t.Helper()
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			h.t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

// due is a time within RenewalThreshold of the harness leaf's expiry.
func (h *renewalHarness) due() time.Time { return harnessIssued.Add(61 * 24 * time.Hour) }

func (h *renewalHarness) stage() CandidateRef {
	h.t.Helper()
	ref, err := stageServerRenewal(h.env())
	if err != nil {
		h.t.Fatalf("stage: %v", err)
	}
	if ref.Outcome != RenewalCandidateStaged {
		h.t.Fatalf("stage outcome = %s, want candidate-staged", ref.Outcome)
	}
	return ref
}

// ----- Stage -----

func TestStageNotDueWritesNothing(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	ref, err := stageServerRenewal(h.env())
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if ref.Outcome != RenewalNotDue || ref.CandidateSHA256 != ([32]byte{}) {
		t.Fatalf("ref = %+v, want not-due without candidate", ref)
	}
	if ref.BaseSHA256 != sha256.Sum256(h.leaf.Raw) || ref.CASHA256 != sha256.Sum256(h.caCert.Raw) {
		t.Fatal("not-due ref must carry the base and CA digests")
	}
	if h.read(pendingServerCertFile) != nil || h.tempMade != 0 {
		t.Fatal("not-due stage must not write")
	}
	h.assertSignersReleased()
}

func TestStageDueWritesOnlyPending(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()

	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
		t.Fatal("stage modified the persisted server certificate")
	}
	pend := h.read(pendingServerCertFile)
	if pend == nil || sha256.Sum256(pend) != ref.CandidateSHA256 {
		t.Fatal("pending candidate missing or not the referenced candidate")
	}
	cand, err := x509.ParseCertificate(pend)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateServerLeaf(cand, h.caCert, &h.srvOpen.key.PublicKey, h.now); err != nil {
		t.Fatalf("staged candidate is not valid: %v", err)
	}
	if verifyPublicKeyMatch(cand, &h.srvOpen.key.PublicKey) != nil {
		t.Fatal("candidate must reuse the existing server key")
	}
	if h.read(prevServerCertFile) != nil {
		t.Fatal("stage must not write a backup")
	}
	h.assertSignersReleased()
	h.assertNoTemps()

	// Serving still loads the persisted (old) certificate.
	m, err := loadServing(h.env())
	if err != nil {
		t.Fatalf("loadServing: %v", err)
	}
	defer m.Close()
	if !m.ServerCertificate.Equal(h.leaf) {
		t.Fatal("serving must keep loading the persisted certificate while a candidate is staged")
	}
}

func TestStageReusesValidPending(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref1 := h.stage()
	pend1 := h.read(pendingServerCertFile)
	writes := h.tempMade

	ref2 := h.stage()
	if ref2 != ref1 {
		t.Fatalf("re-stage returned a different ref: %+v vs %+v", ref2, ref1)
	}
	if !bytes.Equal(h.read(pendingServerCertFile), pend1) || h.tempMade != writes {
		t.Fatal("re-stage must reuse a valid pending candidate without rewriting it")
	}
}

func TestStageReplacesInvalidOrStalePending(t *testing.T) {
	cases := map[string]func(h *renewalHarness) []byte{
		"corrupt":         func(h *renewalHarness) []byte { return []byte("truncated") },
		"same as current": func(h *renewalHarness) []byte { return h.leaf.Raw },
		"foreign CA": func(h *renewalHarness) []byte {
			otherKey := mustKey(t)
			otherCA, _ := generateCAWithSigner(h.now, otherKey)
			leaf, _ := generateServerCertWithSigner(h.now, otherCA, otherKey, h.srvOpen.key)
			return leaf.Raw
		},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			stale := bad(h)
			h.write(pendingServerCertFile, stale)

			ref := h.stage()
			pend := h.read(pendingServerCertFile)
			if bytes.Equal(pend, stale) || sha256.Sum256(pend) != ref.CandidateSHA256 {
				t.Fatal("stale pending candidate was not replaced by a valid candidate")
			}
			if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
				t.Fatal("stage modified the persisted server certificate")
			}
		})
	}
}

func TestStageAcceptsExpiredPreviousLeaf(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = harnessIssued.Add(120 * 24 * time.Hour) // leaf expired, CA valid

	if _, err := loadServing(h.env()); !errors.Is(err, ErrCertificateNotValidNow) {
		t.Fatalf("serving an expired leaf: err = %v, want ErrCertificateNotValidNow", err)
	}
	_, err := reloadExisting(h.env(), reportRenewalDue)
	if !errors.Is(err, ErrRenewalDue) || !errors.Is(err, ErrCertificateNotValidNow) {
		t.Fatalf("reload with expired leaf: err = %v, want ErrRenewalDue and ErrCertificateNotValidNow", err)
	}

	ref := h.stage()
	m, err := loadServingCandidate(h.env(), ref)
	if err != nil {
		t.Fatalf("load candidate after expired base: %v", err)
	}
	m.Close()
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("the expired previous leaf must be kept as the backup bytes")
	}
	m, err = loadServing(h.env())
	if err != nil {
		t.Fatalf("serving after promotion: %v", err)
	}
	m.Close()
	h.assertSignersReleased()
}

func TestStageFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *renewalHarness)
		want  error
	}{
		{"trust absent", func(h *renewalHarness) { h.trust.state = TrustAbsent }, ErrTrustNotHealthy},
		{"trust conflict", func(h *renewalHarness) { h.trust.state = TrustConflict }, ErrTrustNotHealthy},
		{"trust error", func(h *renewalHarness) { h.trust.state, h.trust.err = TrustError, errors.New("store unavailable") }, nil},
		{"CA expired", func(h *renewalHarness) { h.now = h.caCert.NotAfter.Add(time.Hour) }, ErrCertificateNotValidNow},
		{"leaf would outlive CA", func(h *renewalHarness) { h.now = h.caCert.NotAfter.Add(-40 * 24 * time.Hour) }, ErrLeafOutlivesCA},
		{"server DER missing", func(h *renewalHarness) { os.Remove(filepath.Join(h.dir, serverCertFile)) }, ErrInconsistentMachineState},
		{"CA key open fails", func(h *renewalHarness) { h.caOpen.err = ErrKeyNotFound }, ErrKeyNotFound},
		{"server key open fails", func(h *renewalHarness) { h.srvOpen.err = ErrKeyNotFound }, ErrKeyNotFound},
		{"CA key mismatch", func(h *renewalHarness) { h.caOpen.key = mustKey(h.t) }, nil},
		{"server key mismatch", func(h *renewalHarness) { h.srvOpen.key = mustKey(h.t) }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			tc.setup(h)
			before := h.read(serverCertFile)

			ref, err := stageServerRenewal(h.env())
			if err == nil {
				t.Fatalf("stage succeeded with outcome %s, want failure", ref.Outcome)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), before) {
				t.Fatal("a failed stage must not write a candidate or touch the persisted certificate")
			}
			h.assertSignersReleased()
		})
	}
}

// faultTemp wraps a real temp file and fails one step.
type faultTemp struct {
	*os.File
	failWrite, failSync, failClose bool
	// shortWrite writes only a prefix and reports (n, nil), violating the
	// io.Writer contract; partialErr writes a prefix and reports an error.
	shortWrite, partialErr bool
}

func (f *faultTemp) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("injected write failure")
	}
	if f.shortWrite || f.partialErr {
		n, err := f.File.Write(p[:len(p)/2])
		if err == nil && f.partialErr {
			err = errors.New("injected partial write failure")
		}
		return n, err
	}
	return f.File.Write(p)
}

func (f *faultTemp) Sync() error {
	if f.failSync {
		return errors.New("injected sync failure")
	}
	return f.File.Sync()
}

func (f *faultTemp) Close() error {
	err := f.File.Close()
	if f.failClose {
		return errors.New("injected close failure")
	}
	return err
}

func injectTempFault(fsys *fileSystem, mk func(*os.File) tempFile) {
	fsys.createTemp = func(dir, pattern string) (tempFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return mk(f), nil
	}
}

func TestStageWriteFaults(t *testing.T) {
	cases := map[string]func(fsys *fileSystem){
		"create temp": func(fsys *fileSystem) {
			fsys.createTemp = func(string, string) (tempFile, error) { return nil, errors.New("injected create failure") }
		},
		"write": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, failWrite: true} })
		},
		"sync": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, failSync: true} })
		},
		"close": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, failClose: true} })
		},
		"replace": func(fsys *fileSystem) {
			fsys.replace = func(string, string) error { return errors.New("injected replace failure") }
		},
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			inject(&h.fs)
			if _, err := stageServerRenewal(h.env()); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("err = %v, want the injected failure", err)
			}
			if h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
				t.Fatal("a failed candidate write must leave no candidate and the persisted certificate unchanged")
			}
			h.assertNoTemps()
			h.assertSignersReleased()
		})
	}
}

func TestStageRemovesOnlyReservedOrphanTemps(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	h.write(tempPrefix+"orphan", []byte("x"))
	h.write(".tmp-legacy", []byte("x"))
	h.write("unrelated.txt", []byte("x"))
	h.stage()
	if h.read(tempPrefix+"orphan") != nil {
		t.Fatal("reserved orphan temp not removed")
	}
	if h.read(".tmp-legacy") == nil || h.read("unrelated.txt") == nil {
		t.Fatal("files without the reserved prefix must never be removed")
	}
}

// ----- LoadServingCandidate -----

func TestLoadServingCandidateSuccess(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()

	m, err := loadServingCandidate(h.env(), ref)
	if err != nil {
		t.Fatalf("load candidate: %v", err)
	}
	if sha256.Sum256(m.ServerCertificate.Raw) != ref.CandidateSHA256 {
		t.Fatal("loaded material is not the referenced candidate")
	}
	if len(h.caOpen.opened) != 1 { // stage only; candidate load never opens the CA key
		t.Fatalf("CA key opened %d times, want only by stage", len(h.caOpen.opened))
	}
	last := h.srvOpen.opened[len(h.srvOpen.opened)-1]
	if last.closed {
		t.Fatal("the candidate's server signer must be transferred to the caller open")
	}
	if err := m.Close(); err != nil || !last.closed {
		t.Fatal("Material.Close must release the candidate's server signer")
	}
	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
		t.Fatal("loading a candidate must not change the persisted certificate")
	}
}

func TestLoadServingCandidateFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *renewalHarness, ref *CandidateRef)
		want  error
	}{
		{"zero ref", func(h *renewalHarness, ref *CandidateRef) { *ref = CandidateRef{} }, ErrNoCandidate},
		{"not-due ref", func(h *renewalHarness, ref *CandidateRef) { ref.Outcome = RenewalNotDue }, ErrNoCandidate},
		{"pending missing", func(h *renewalHarness, ref *CandidateRef) { os.Remove(filepath.Join(h.dir, pendingServerCertFile)) }, ErrCandidateNotFound},
		{"pending replaced", func(h *renewalHarness, ref *CandidateRef) { ref.CandidateSHA256[0] ^= 0xff }, ErrCandidateMismatch},
		{"base changed", func(h *renewalHarness, ref *CandidateRef) { ref.BaseSHA256[0] ^= 0xff }, ErrCandidateStale},
		{"CA changed", func(h *renewalHarness, ref *CandidateRef) { ref.CASHA256[0] ^= 0xff }, ErrCandidateStale},
		{"trust absent", func(h *renewalHarness, ref *CandidateRef) { h.trust.state = TrustAbsent }, ErrTrustNotHealthy},
		{"candidate expired", func(h *renewalHarness, ref *CandidateRef) { h.now = h.now.Add(100 * 24 * time.Hour) }, ErrCertificateNotValidNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			ref := h.stage()
			tc.setup(h, &ref)
			if _, err := loadServingCandidate(h.env(), ref); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			h.assertSignersReleased()
		})
	}
}

// ----- ConfirmServingCandidate -----

func TestConfirmPromotesWithBackup(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	cand := h.read(pendingServerCertFile)

	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !bytes.Equal(h.read(serverCertFile), cand) {
		t.Fatal("persisted certificate is not the candidate after confirm")
	}
	if !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("backup must hold the previous persisted certificate")
	}
	if h.read(pendingServerCertFile) != nil {
		t.Fatal("pending candidate must be consumed by the promotion")
	}
	h.assertSignersReleased()
	h.assertNoTemps()

	m, err := loadServing(h.env())
	if err != nil {
		t.Fatalf("serving after promotion: %v", err)
	}
	defer m.Close()
	if sha256.Sum256(m.ServerCertificate.Raw) != ref.CandidateSHA256 {
		t.Fatal("serving does not load the promoted certificate")
	}
}

func TestConfirmRetryAfterCompletionPreservesBackup(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	writes := h.tempMade
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("retry confirm: %v", err)
	}
	if h.tempMade != writes || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("a retry after completed promotion must not rewrite the backup")
	}
}

func TestConfirmLostResponseAfterPromote(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	cand := h.read(pendingServerCertFile)

	real := h.fs.replace
	h.fs.replace = func(oldpath, newpath string) error {
		if filepath.Base(oldpath) != pendingServerCertFile {
			return real(oldpath, newpath)
		}
		if err := real(oldpath, newpath); err != nil {
			return err
		}
		return errors.New("injected lost response after rename")
	}
	err := confirmServingCandidate(h.env(), ref)
	if !errors.Is(err, ErrPromotionUnconfirmed) {
		t.Fatalf("err = %v, want ErrPromotionUnconfirmed", err)
	}
	if !bytes.Equal(h.read(serverCertFile), cand) {
		t.Fatal("precondition: the rename took effect")
	}

	h.fs.replace = real
	writes := h.tempMade
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("retry after lost response: %v", err)
	}
	if h.tempMade != writes || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("retry after lost response must keep the original backup")
	}
}

func TestConfirmPromoteFailsBeforeEffect(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	cand := h.read(pendingServerCertFile)

	real := h.fs.replace
	h.fs.replace = func(oldpath, newpath string) error {
		if filepath.Base(oldpath) == pendingServerCertFile {
			return errors.New("injected promote failure")
		}
		return real(oldpath, newpath)
	}
	if err := confirmServingCandidate(h.env(), ref); !errors.Is(err, ErrPromotionUnconfirmed) {
		t.Fatalf("err = %v, want ErrPromotionUnconfirmed", err)
	}
	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || !bytes.Equal(h.read(pendingServerCertFile), cand) {
		t.Fatal("a failed promote must keep the persisted certificate and the candidate")
	}
	if !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("backup must have been written before the promote")
	}

	// Restart/retry from state active=old, prev=old, pending=new.
	h.fs.replace = real
	writes := h.tempMade
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if h.tempMade != writes {
		t.Fatal("retry must not rewrite a backup that already holds the current bytes")
	}
	if !bytes.Equal(h.read(serverCertFile), cand) || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("retry did not complete the promotion with the original backup")
	}
}

func TestConfirmBackupFaults(t *testing.T) {
	cases := map[string]func(fsys *fileSystem){
		"create temp": func(fsys *fileSystem) {
			fsys.createTemp = func(string, string) (tempFile, error) { return nil, errors.New("injected create failure") }
		},
		"write": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, failWrite: true} })
		},
		"sync": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, failSync: true} })
		},
		"close": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, failClose: true} })
		},
		"short write": func(fsys *fileSystem) {
			injectTempFault(fsys, func(f *os.File) tempFile { return &faultTemp{File: f, shortWrite: true} })
		},
		"replace": func(fsys *fileSystem) {
			fsys.replace = func(oldpath, newpath string) error { return errors.New("injected backup replace failure") }
		},
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			ref := h.stage()
			cand := h.read(pendingServerCertFile)
			inject(&h.fs)
			err := confirmServingCandidate(h.env(), ref)
			if err == nil || errors.Is(err, ErrPromotionUnconfirmed) || !strings.Contains(err.Error(), "back up") {
				t.Fatalf("err = %v, want a backup failure before any promotion", err)
			}
			if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || !bytes.Equal(h.read(pendingServerCertFile), cand) || h.read(prevServerCertFile) != nil {
				t.Fatal("a failed backup must not promote and must not leave a partial backup")
			}
			h.assertNoTemps()
			h.assertSignersReleased()
		})
	}
}

func TestConfirmFailsClosedWithoutChanges(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *renewalHarness, ref *CandidateRef)
		want  error
	}{
		{"zero ref", func(h *renewalHarness, ref *CandidateRef) { *ref = CandidateRef{} }, ErrNoCandidate},
		{"pending replaced by re-stage", func(h *renewalHarness, ref *CandidateRef) {
			os.Remove(filepath.Join(h.dir, pendingServerCertFile))
			h.stage()
		}, ErrCandidateMismatch},
		{"pending missing", func(h *renewalHarness, ref *CandidateRef) { os.Remove(filepath.Join(h.dir, pendingServerCertFile)) }, ErrCandidateNotFound},
		{"base changed", func(h *renewalHarness, ref *CandidateRef) { ref.BaseSHA256[0] ^= 0xff }, ErrCandidateStale},
		{"CA changed", func(h *renewalHarness, ref *CandidateRef) { ref.CASHA256[0] ^= 0xff }, ErrCandidateStale},
		{"trust conflict", func(h *renewalHarness, ref *CandidateRef) { h.trust.state = TrustConflict }, ErrTrustNotHealthy},
		{"candidate expired at confirm", func(h *renewalHarness, ref *CandidateRef) { h.now = h.now.Add(100 * 24 * time.Hour) }, ErrCertificateNotValidNow},
		{"server key open fails", func(h *renewalHarness, ref *CandidateRef) { h.srvOpen.err = ErrKeyNotFound }, ErrKeyNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			ref := h.stage()
			tc.setup(h, &ref)
			active, pending := h.read(serverCertFile), h.read(pendingServerCertFile)

			if err := confirmServingCandidate(h.env(), ref); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !bytes.Equal(h.read(serverCertFile), active) || !bytes.Equal(h.read(pendingServerCertFile), pending) || h.read(prevServerCertFile) != nil {
				t.Fatal("a rejected confirm must not change any persisted file")
			}
			h.assertSignersReleased()
		})
	}
}

func TestConfirmRetryLeavesForeignPendingUntouched(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	foreign := []byte("foreign pending")
	h.write(pendingServerCertFile, foreign)
	if err := confirmServingCandidate(h.env(), ref); !errors.Is(err, ErrCandidateMismatch) {
		t.Fatalf("err = %v, want ErrCandidateMismatch", err)
	}
	if !bytes.Equal(h.read(pendingServerCertFile), foreign) || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("a foreign pending file and the backup must be left untouched")
	}
}

// ----- AbandonServingCandidate -----

func TestAbandonServingCandidate(t *testing.T) {
	t.Run("matching", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		h.now = h.due()
		ref := h.stage()
		opens, trustCalls := len(h.caOpen.opened)+len(h.srvOpen.opened), h.trust.calls
		if err := abandonServingCandidate(h.env(), ref); err != nil {
			t.Fatalf("abandon: %v", err)
		}
		if h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || h.read(prevServerCertFile) != nil {
			t.Fatal("abandon must remove only the pending candidate")
		}
		if len(h.caOpen.opened)+len(h.srvOpen.opened) != opens || h.trust.calls != trustCalls {
			t.Fatal("abandon must not open keys or consult trust")
		}
		if err := abandonServingCandidate(h.env(), ref); err != nil {
			t.Fatalf("repeated abandon must be an idempotent no-op: %v", err)
		}
	})
	t.Run("mismatch keeps pending", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		h.now = h.due()
		ref := h.stage()
		ref.CandidateSHA256[0] ^= 0xff
		if err := abandonServingCandidate(h.env(), ref); !errors.Is(err, ErrCandidateMismatch) {
			t.Fatalf("err = %v, want ErrCandidateMismatch", err)
		}
		if h.read(pendingServerCertFile) == nil {
			t.Fatal("a mismatching abandon must not delete the pending candidate")
		}
	})
	t.Run("after promotion", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		h.now = h.due()
		ref := h.stage()
		if err := confirmServingCandidate(h.env(), ref); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		if err := abandonServingCandidate(h.env(), ref); !errors.Is(err, ErrCandidatePromoted) {
			t.Fatalf("err = %v, want ErrCandidatePromoted", err)
		}
		if sha256.Sum256(h.read(serverCertFile)) != ref.CandidateSHA256 || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
			t.Fatal("abandon must never reverse a completed promotion")
		}
	})
	t.Run("zero ref", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		if err := abandonServingCandidate(h.env(), CandidateRef{}); !errors.Is(err, ErrNoCandidate) {
			t.Fatalf("err = %v, want ErrNoCandidate", err)
		}
	})
}

// ----- serving and reload validation -----

func TestLoadServingFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *renewalHarness)
		want  error
	}{
		{"trust absent", func(h *renewalHarness) { h.trust.state = TrustAbsent }, ErrTrustNotHealthy},
		{"trust conflict", func(h *renewalHarness) { h.trust.state = TrustConflict }, ErrTrustNotHealthy},
		{"leaf expired", func(h *renewalHarness) { h.now = harnessIssued.Add(91 * 24 * time.Hour) }, ErrCertificateNotValidNow},
		{"before CA and leaf validity", func(h *renewalHarness) { h.now = harnessIssued.Add(-time.Hour) }, ErrCertificateNotValidNow},
		{"leaf not yet valid, CA valid", func(h *renewalHarness) { h.persistFutureLeaf() }, ErrCertificateNotValidNow},
		{"server key mismatch", func(h *renewalHarness) { h.srvOpen.key = mustKey(h.t) }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			tc.setup(h)
			_, err := loadServing(h.env())
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			h.assertSignersReleased()
			if len(h.caOpen.opened) != 0 {
				t.Fatal("serving must never open the CA key")
			}
		})
	}
}

// issueLeaf signs a server certificate with an explicit template for
// validator tests.
func issueLeaf(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, pub crypto.PublicKey, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: serverCN, Organization: []string{serverOrg}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage:  eku,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestValidateServerLeafRejects(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	pub := &h.srvOpen.key.PublicKey
	now := harnessIssued.Add(time.Hour)
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	if err := validateServerLeaf(h.leaf, h.caCert, pub, now); err != nil {
		t.Fatalf("baseline leaf rejected: %v", err)
	}
	outliving := issueLeaf(t, h.caCert, h.caKey, pub, now, h.caCert.NotAfter.Add(24*time.Hour), serverAuth)
	if err := validateServerLeaf(outliving, h.caCert, pub, now); !errors.Is(err, ErrLeafOutlivesCA) {
		t.Fatalf("leaf outliving CA: err = %v, want ErrLeafOutlivesCA", err)
	}
	clientAuth := issueLeaf(t, h.caCert, h.caKey, pub, now, now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := validateServerLeaf(clientAuth, h.caCert, pub, now); err == nil {
		t.Fatal("leaf without serverAuth EKU accepted")
	}
	futureCA, _ := generateCAWithSigner(now.Add(48*time.Hour), h.caKey)
	if err := validateServerLeaf(h.leaf, futureCA, pub, now); !errors.Is(err, ErrCertificateNotValidNow) {
		t.Fatalf("not-yet-valid CA: err = %v, want ErrCertificateNotValidNow", err)
	}
}

func TestReloadExistingNeverRenews(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	m, err := reloadExisting(h.env(), reportRenewalDue)
	if err != nil {
		t.Fatalf("reload not due: %v", err)
	}
	if h.caOpen.unclosed() != 0 || h.srvOpen.unclosed() != 1 {
		t.Fatal("reload must release the CA signer and transfer the server signer")
	}
	m.Close()

	h.now = h.due()
	if _, err := reloadExisting(h.env(), reportRenewalDue); !errors.Is(err, ErrRenewalDue) || errors.Is(err, ErrCertificateNotValidNow) {
		t.Fatalf("reload when due: err = %v, want ErrRenewalDue only", err)
	}
	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || h.read(pendingServerCertFile) != nil || h.tempMade != 0 {
		t.Fatal("reload must never write")
	}
	h.assertSignersReleased()

	h.trust.state = TrustAbsent
	h.now = harnessIssued
	if _, err := reloadExisting(h.env(), reportRenewalDue); !errors.Is(err, ErrTrustNotHealthy) {
		t.Fatalf("reload with absent trust: err = %v, want ErrTrustNotHealthy", err)
	}
	h.assertSignersReleased()
}

func TestStatExistsDistinguishesAccessErrors(t *testing.T) {
	fsys := osFS
	fsys.stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	if ok, err := fsys.statExists("x"); ok || err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("statExists on access error = (%v, %v), want an error", ok, err)
	}
	fsys.stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }
	if ok, err := fsys.statExists("x"); ok || err != nil {
		t.Fatalf("statExists on not-exist = (%v, %v), want (false, nil)", ok, err)
	}
}

// ----- not-yet-valid leaf, write faults and reload policies -----

// persistFutureLeaf replaces the persisted server certificate with a leaf
// signed by the (already valid) CA whose validity starts in the future, and
// sets now inside the CA validity but before the leaf's NotBefore.
func (h *renewalHarness) persistFutureLeaf() {
	h.t.Helper()
	start := harnessIssued.Add(48 * time.Hour)
	leaf := issueLeaf(h.t, h.caCert, h.caKey, &h.srvOpen.key.PublicKey, start, start.Add(60*24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	h.write(serverCertFile, leaf.Raw)
	h.now = harnessIssued.Add(time.Hour)
}

func TestAtomicWriteShortWrite(t *testing.T) {
	for name, ft := range map[string]faultTemp{
		"short write with nil error": {shortWrite: true},
		"partial write with error":   {partialErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target.der")
			if err := os.WriteFile(target, []byte("previous"), 0600); err != nil {
				t.Fatal(err)
			}
			fsys := osFS
			replaced := 0
			fsys.replace = func(o, n string) error { replaced++; return replaceFile(o, n) }
			injectTempFault(&fsys, func(f *os.File) tempFile { c := ft; c.File = f; return &c })

			err := fsys.atomicWrite(target, []byte("0123456789"), 0600)
			if err == nil {
				t.Fatal("a short write must fail")
			}
			if ft.shortWrite && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("err = %v, want io.ErrShortWrite", err)
			}
			if replaced != 0 {
				t.Fatal("a short write must never reach the replace")
			}
			got, _ := os.ReadFile(target)
			entries, _ := os.ReadDir(dir)
			if string(got) != "previous" || len(entries) != 1 {
				t.Fatal("a short write must leave the target unchanged and remove its temp file")
			}
		})
	}
}

func TestStageShortWriteLeavesNoCandidate(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	injectTempFault(&h.fs, func(f *os.File) tempFile { return &faultTemp{File: f, shortWrite: true} })
	if _, err := stageServerRenewal(h.env()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err = %v, want io.ErrShortWrite", err)
	}
	if h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
		t.Fatal("a short candidate write must leave no candidate and the persisted certificate unchanged")
	}
	h.assertNoTemps()
	h.assertSignersReleased()
}

// replaceThenFail performs the real replace for targets named target and then
// reports an error, modelling an error returned after the rename took effect.
func replaceThenFail(real func(string, string) error, target string) func(string, string) error {
	return func(oldpath, newpath string) error {
		if err := real(oldpath, newpath); err != nil {
			return err
		}
		if filepath.Base(newpath) == target {
			return errors.New("injected error after replace took effect")
		}
		return nil
	}
}

func TestStagePendingReplacePostEffectError(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	real := h.fs.replace
	h.fs.replace = replaceThenFail(real, pendingServerCertFile)

	if _, err := stageServerRenewal(h.env()); err == nil {
		t.Fatal("stage must report the replace error")
	}
	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
		t.Fatal("stage must never change the persisted certificate")
	}
	landed := h.read(pendingServerCertFile)
	if landed == nil {
		t.Fatal("precondition: the pending replace took effect")
	}

	// The next stage reconciles: the complete, valid pending candidate is
	// reused rather than rewritten.
	h.fs.replace = real
	writes := h.tempMade
	ref := h.stage()
	if ref.CandidateSHA256 != sha256.Sum256(landed) || h.tempMade != writes {
		t.Fatal("re-stage must reconcile to the candidate that landed")
	}
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("confirm after reconciled stage: %v", err)
	}
}

func TestConfirmBackupReplacePostEffectError(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	cand := h.read(pendingServerCertFile)
	real := h.fs.replace
	h.fs.replace = replaceThenFail(real, prevServerCertFile)

	err := confirmServingCandidate(h.env(), ref)
	if err == nil || errors.Is(err, ErrPromotionUnconfirmed) {
		t.Fatalf("err = %v, want a backup error before any promotion", err)
	}
	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || !bytes.Equal(h.read(pendingServerCertFile), cand) {
		t.Fatal("a backup error must preserve the persisted certificate and the candidate")
	}
	if !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("precondition: the backup replace took effect")
	}

	h.fs.replace = real
	writes := h.tempMade
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if h.tempMade != writes {
		t.Fatal("retry must reuse the matching backup without rewriting it")
	}
	if !bytes.Equal(h.read(serverCertFile), cand) || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("retry did not promote with the original backup")
	}
}

func TestReloadExistingPolicies(t *testing.T) {
	t.Run("valid within renewal window", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		h.now = h.due()
		if _, err := reloadExisting(h.env(), reportRenewalDue); !errors.Is(err, ErrRenewalDue) {
			t.Fatalf("ReloadMachine policy: err = %v, want ErrRenewalDue", err)
		}
		h.assertSignersReleased()

		m, err := reloadExisting(h.env(), verifyExistingState)
		if err != nil {
			t.Fatalf("provisioning policy: err = %v, want nil", err)
		}
		if !m.ServerCertificate.Equal(h.leaf) || h.caOpen.unclosed() != 0 || h.srvOpen.unclosed() != 1 {
			t.Fatal("provisioning policy must return the existing leaf with only the server signer open")
		}
		m.Close()
		if h.tempMade != 0 || h.read(pendingServerCertFile) != nil {
			t.Fatal("no policy may write")
		}
	})
	failures := []struct {
		name  string
		setup func(h *renewalHarness)
		want  []error
	}{
		{"expired", func(h *renewalHarness) { h.now = harnessIssued.Add(91 * 24 * time.Hour) }, []error{ErrRenewalDue, ErrCertificateNotValidNow}},
		{"leaf not yet valid", func(h *renewalHarness) { h.persistFutureLeaf() }, []error{ErrCertificateNotValidNow}},
		{"trust conflict", func(h *renewalHarness) { h.now = h.due(); h.trust.state = TrustConflict }, []error{ErrTrustNotHealthy}},
		{"leaf outlives CA", func(h *renewalHarness) {
			h.now = h.caCert.NotAfter.Add(-10 * 24 * time.Hour)
			leaf := issueLeaf(h.t, h.caCert, h.caKey, &h.srvOpen.key.PublicKey, h.now.Add(-time.Hour), h.caCert.NotAfter.Add(50*24*time.Hour),
				[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
			h.write(serverCertFile, leaf.Raw)
		}, []error{ErrLeafOutlivesCA}},
	}
	for _, tc := range failures {
		for _, policy := range []reloadPolicy{reportRenewalDue, verifyExistingState} {
			t.Run(fmt.Sprintf("%s/policy %d", tc.name, policy), func(t *testing.T) {
				h := newRenewalHarness(t, harnessIssued)
				tc.setup(h)
				m, err := reloadExisting(h.env(), policy)
				for _, want := range tc.want {
					if !errors.Is(err, want) {
						t.Fatalf("err = %v, want %v", err, want)
					}
				}
				if m.ServerCertificate != nil || m.Certificate.PrivateKey != nil {
					t.Fatal("a failure must return a zero Material")
				}
				h.assertSignersReleased()
			})
		}
	}
}
