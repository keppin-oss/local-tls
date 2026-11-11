package localtls

// Offline tests of the serving-close harness. They use an in-memory fake
// signer and synthetic traces only: no CNG key, no trust store, no file
// outside t.TempDir.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fake signer ----

var errFakeSignerClosed = errors.New("fake signer closed")

// fakeCCSigner models only the controlled outcomes the harness needs: an
// in-memory ECDSA key, a RWMutex and a closed flag like the cng contract, and
// configurable defects. It is not a second implementation of cng.
type fakeCCSigner struct {
	key *ecdsa.PrivateKey

	mu     sync.RWMutex
	closed bool
	signs  atomic.Int32
	closes atomic.Int32

	acceptAfterClose bool          // defect: Sign keeps working after Close
	failSignAt       int32         // 1-based Sign number that fails (0: none)
	panicSignAt      int32         // 1-based Sign number that panics (0: none)
	closeErr         error         // returned by the first Close
	closeBlock       chan struct{} // first Close waits on it before locking
	closeEntered     chan struct{} // closed when the first Close starts
	publicOverride   crypto.PublicKey
}

func newFakeCCSigner(t *testing.T) *fakeCCSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCCSigner{key: k}
}

func (f *fakeCCSigner) Public() crypto.PublicKey {
	if f.publicOverride != nil {
		return f.publicOverride
	}
	return f.key.Public()
}

func (f *fakeCCSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n := f.signs.Add(1)
	if f.panicSignAt != 0 && n == f.panicSignAt {
		panic("fake sign panic")
	}
	if f.closed && !f.acceptAfterClose {
		return nil, errFakeSignerClosed
	}
	if f.failSignAt != 0 && n == f.failSignAt {
		return nil, errors.New("fake native sign failure")
	}
	return f.key.Sign(r, digest, opts)
}

func (f *fakeCCSigner) Close() error {
	if f.closes.Add(1) == 1 {
		if f.closeEntered != nil {
			close(f.closeEntered)
		}
		if f.closeBlock != nil {
			<-f.closeBlock
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.closeErr
}

var ccOfflineConfig = ccConfig{
	PipeDeadline:  5 * time.Second,
	Watchdog:      20 * time.Second,
	RoundWatchdog: 20 * time.Second,
	Quiesce:       5 * time.Second,
	C1Pairs:       8,
	C3Workers:     4,
	C3Threshold:   10,
	C3Rounds:      3,
}

func ccTestFixture(t *testing.T, s crypto.Signer) *ccFixture {
	t.Helper()
	fx, err := newCCFixture(time.Now(), s)
	if err != nil {
		t.Fatal(err)
	}
	return fx
}

// waitLeftover joins every goroutine of a scenario before the subtest ends.
func waitLeftover(t *testing.T, obs ccObservation) {
	t.Helper()
	select {
	case <-obs.leftover:
	case <-time.After(10 * time.Second):
		t.Fatal("scenario goroutines did not terminate after release")
	}
}

func requireFinding(t *testing.T, v ccVerdict, rule string, out ccOutcome) {
	t.Helper()
	if !v.has(rule, out) {
		t.Fatalf("missing finding %s %s in verdict:\n%s", rule, out, v)
	}
}

// ---- verifier: synthetic traces ----

type ccTraceBuilder struct {
	seq    uint64
	events []ccEvent
}

func (b *ccTraceBuilder) ev(kind ccEventKind, conn int, ok bool) *ccTraceBuilder {
	b.seq++
	var err error
	if !ok {
		err = errors.New("synthetic")
	}
	b.events = append(b.events, ccEvent{Seq: b.seq, Kind: kind, Conn: conn, OK: ok, Err: err})
	return b
}

func (b *ccTraceBuilder) sign(conn int, ok bool) *ccTraceBuilder {
	return b.ev(ccSignCall, conn, true).ev(ccSignReturn, conn, ok)
}

func (b *ccTraceBuilder) close1(ok bool) *ccTraceBuilder {
	return b.ev(ccClose1Call, ccNoConn, true).ev(ccClose1Return, ccNoConn, ok)
}

func (b *ccTraceBuilder) close2(ok bool) *ccTraceBuilder {
	return b.ev(ccClose2Call, ccNoConn, true).ev(ccClose2Return, ccNoConn, ok)
}

func okPair(id int) ccPairResult { return ccPairResult{ID: id, Version: tls.VersionTLS13} }

func failedPair(id int) ccPairResult {
	return ccPairResult{ID: id, Version: tls.VersionTLS13, ServerErr: errors.New("srv"), ClientErr: errors.New("cli")}
}

func ccObs(b *ccTraceBuilder, pairs ...ccPairResult) ccObservation {
	return ccObservation{Scenario: "synthetic", Events: b.events, Pairs: pairs, ExpectClose2: true, Quiescent: true}
}

func TestServingCloseHarnessVerifierTable(t *testing.T) {
	type tc struct {
		name    string
		obs     func() ccObservation
		outcome ccOutcome
		rule    string // a finding that must be present ("" for PASS)
		ruleOut ccOutcome
		release bool
	}
	cases := []tc{
		{
			name: "C1 nominal: drained pairs, Close1, POST probe fails, Close2",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).sign(1, true).close1(true).sign(2, false).close2(true)
				return ccObs(b, okPair(0), okPair(1), failedPair(2))
			},
			outcome: ccPass, release: true,
		},
		{
			name: "C2 nominal: gate arrival, Close1, release, Sign fails",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccGateArrive, 0, true).close1(true).
					ev(ccGateRelease, 0, true).ev(ccSignReturn, 0, false).close2(true)
				o := ccObs(b, failedPair(0))
				o.Gate = &ccGateExpectation{Conn: 0}
				return o
			},
			outcome: ccPass, release: true,
		},
		{
			name: "signature produced before Close, its return registered after Close1Return (legal)",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).close1(true).ev(ccSignReturn, 0, true).close2(true)
				return ccObs(b, okPair(0))
			},
			outcome: ccPass, release: true,
		},
		{
			name: "overlapping Sign fails: compatible with Close",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccClose1Call, ccNoConn, true).
					ev(ccSignReturn, 0, false).ev(ccClose1Return, ccNoConn, true).close2(true)
				return ccObs(b, failedPair(0))
			},
			outcome: ccPass, release: true,
		},
		{
			name: "R1: Sign called after Close1Return succeeds",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).close1(true).sign(0, true).close2(true)
				return ccObs(b, okPair(0))
			},
			outcome: ccViolation, rule: "R1", ruleOut: ccViolation, release: true,
		},
		{
			name: "R2: PRE Sign fails",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, false).close1(true).close2(true)
				return ccObs(b, failedPair(0))
			},
			outcome: ccNonPositive, rule: "R2", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R2: Close absent is explicit, PRE failure is still caught",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, false)
				o := ccObs(b, failedPair(0))
				o.ExpectClose2 = false
				return o
			},
			outcome: ccReleaseUnconfirmed, rule: "R2", ruleOut: ccNonPositive, release: false,
		},
		{
			name: "R4: successful pair fails client verification",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				p := okPair(0)
				p.CheckErr = errors.New("wrong leaf")
				return ccObs(b, p)
			},
			outcome: ccNonPositive, rule: "R4", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: client fails while its Sign succeeded",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				return ccObs(b, failedPair(0))
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: server succeeded, client failed",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).close1(true).sign(0, false).close2(true)
				p := okPair(0)
				p.ClientErr = errors.New("cli")
				return ccObs(b, p)
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: Sign on a wrong connection id",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).sign(7, true).close1(true).close2(true)
				return ccObs(b, okPair(0))
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: POST pair fails without reaching Sign",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).close1(true).close2(true)
				return ccObs(b, failedPair(0))
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: timeout is not absorbed as an expected failure",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).close1(true).sign(0, false).close2(true)
				p := failedPair(0)
				p.ClientTimeout = true
				return ccObs(b, p)
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R6: first Close fails, second returns nil: release stays unconfirmed",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(false).close2(true)
				return ccObs(b, okPair(0))
			},
			outcome: ccReleaseUnconfirmed, rule: "R6", ruleOut: ccReleaseUnconfirmed, release: false,
		},
		{
			name: "R8: Close pending (R6 too, R8 must be present)",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).ev(ccClose1Call, ccNoConn, true)
				o := ccObs(b, okPair(0))
				o.Quiescent = false
				o.WatchdogFired = true
				return o
			},
			outcome: ccReleaseUnconfirmed, rule: "R8", ruleOut: ccReleaseUnconfirmed, release: false,
		},
		{
			name: "R8: worker not terminated",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				o := ccObs(b, okPair(0))
				o.Quiescent = false
				return o
			},
			outcome: ccReleaseUnconfirmed, rule: "R8", ruleOut: ccReleaseUnconfirmed, release: false,
		},
		{
			name: "R8: recovered panic vetoes release even with nil Closes and quiescence",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				o := ccObs(b, okPair(0))
				o.Panics = []string{"boom"}
				return o
			},
			outcome: ccReleaseUnconfirmed, rule: "R8", ruleOut: ccReleaseUnconfirmed, release: false,
		},
		{
			name: "R8: watchdog expired but quiescent: non-positive, release confirmed",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				o := ccObs(b, okPair(0))
				o.WatchdogFired = true
				return o
			},
			outcome: ccNonPositive, rule: "R8", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R7: second Close returns an error",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(false)
				return ccObs(b, okPair(0))
			},
			outcome: ccNonPositive, rule: "R7", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R7: second Close missing when expected",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true)
				return ccObs(b, okPair(0))
			},
			outcome: ccNonPositive, rule: "R7", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "C2: gated Sign released after Close1Return succeeds",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccGateArrive, 0, true).close1(true).
					ev(ccGateRelease, 0, true).ev(ccSignReturn, 0, true).close2(true)
				o := ccObs(b, okPair(0))
				o.Gate = &ccGateExpectation{Conn: 0}
				return o
			},
			outcome: ccViolation, rule: "C2", ruleOut: ccViolation, release: true,
		},
		{
			name: "C2: order not proven (release before Close1Return)",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccGateArrive, 0, true).ev(ccGateRelease, 0, true).
					ev(ccClose1Call, ccNoConn, true).ev(ccSignReturn, 0, false).ev(ccClose1Return, ccNoConn, true).close2(true)
				o := ccObs(b, failedPair(0))
				o.Gate = &ccGateExpectation{Conn: 0}
				return o
			},
			outcome: ccNonPositive, rule: "C2", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "S: C1 expectations met",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).sign(1, true).close1(true).sign(2, false).close2(true)
				o := ccObs(b, okPair(0), okPair(1), failedPair(2))
				o.Expect = &ccExpect{Kind: ccKindC1, DrainedPairs: 2, ProbeID: 2}
				return o
			},
			outcome: ccPass, release: true,
		},
		{
			name: "S: C1 with only successful Closes and no pair is not a PASS",
			obs: func() ccObservation {
				o := ccObs((&ccTraceBuilder{}).close1(true).close2(true))
				o.Expect = &ccExpect{Kind: ccKindC1, DrainedPairs: 2, ProbeID: 2}
				return o
			},
			outcome: ccNonPositive, rule: "S", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "S: C1 without the probe is not a PASS",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).sign(1, true).close1(true).close2(true)
				o := ccObs(b, okPair(0), okPair(1))
				o.Expect = &ccExpect{Kind: ccKindC1, DrainedPairs: 2, ProbeID: 2}
				return o
			},
			outcome: ccNonPositive, rule: "S", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "S: C2 with an extra pair",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccGateArrive, 0, true).close1(true).
					ev(ccGateRelease, 0, true).ev(ccSignReturn, 0, false).sign(1, false).close2(true)
				o := ccObs(b, failedPair(0), failedPair(1))
				o.Gate = &ccGateExpectation{Conn: 0}
				o.Expect = &ccExpect{Kind: ccKindC2, GateConn: 0}
				return o
			},
			outcome: ccNonPositive, rule: "S", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "S: C3 below threshold and without POST pairs",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				o := ccObs(b, okPair(0))
				o.Expect = &ccExpect{Kind: ccKindC3, MinVerified: 3, PostPairs: 2}
				return o
			},
			outcome: ccNonPositive, rule: "S", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: duplicate pair id",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).close1(true).close2(true)
				return ccObs(b, okPair(0), failedPair(0))
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
		{
			name: "R5: two Signs on one connection",
			obs: func() ccObservation {
				b := (&ccTraceBuilder{}).sign(0, true).sign(0, true).close1(true).close2(true)
				return ccObs(b, okPair(0))
			},
			outcome: ccNonPositive, rule: "R5", ruleOut: ccNonPositive, release: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := verifyCC(c.obs())
			if v.Outcome != c.outcome {
				t.Fatalf("outcome = %s, want %s\n%s", v.Outcome, c.outcome, v)
			}
			if v.ReleaseConfirmed != c.release {
				t.Fatalf("release confirmed = %v, want %v\n%s", v.ReleaseConfirmed, c.release, v)
			}
			if c.rule != "" {
				requireFinding(t, v, c.rule, c.ruleOut)
			} else if len(v.Findings) != 0 {
				t.Fatalf("unexpected findings:\n%s", v)
			}
		})
	}
}

// ---- client verification oracle ----

func TestServingCloseHarnessClientStateCheck(t *testing.T) {
	s := newFakeCCSigner(t)
	fx := ccTestFixture(t, s)
	other := ccTestFixture(t, s) // another CA and leaf for the same key
	good := func() tls.ConnectionState {
		return tls.ConnectionState{
			Version:           tls.VersionTLS13,
			HandshakeComplete: true,
			ServerName:        "localhost",
			PeerCertificates:  []*x509.Certificate{fx.leaf},
			VerifiedChains:    [][]*x509.Certificate{{fx.leaf, fx.ca}},
		}
	}
	if err := checkCCClientState(good(), fx, tls.VersionTLS13); err != nil {
		t.Fatalf("good state rejected: %v", err)
	}
	mutations := map[string]func(*tls.ConnectionState){
		"wrong hostname":  func(st *tls.ConnectionState) { st.ServerName = "example.test" },
		"wrong CA":        func(st *tls.ConnectionState) { st.VerifiedChains = [][]*x509.Certificate{{fx.leaf, other.ca}} },
		"wrong leaf hash": func(st *tls.ConnectionState) { st.PeerCertificates = []*x509.Certificate{other.leaf} },
		"resumed":         func(st *tls.ConnectionState) { st.DidResume = true },
		"wrong version":   func(st *tls.ConnectionState) { st.Version = tls.VersionTLS12 },
		"no chain":        func(st *tls.ConnectionState) { st.VerifiedChains = nil },
		"incomplete":      func(st *tls.ConnectionState) { st.HandshakeComplete = false },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			st := good()
			mutate(&st)
			if err := checkCCClientState(st, fx, tls.VersionTLS13); err == nil {
				t.Fatal("mutated state accepted")
			}
		})
	}
}

// ---- runner with the correct fake ----

func TestServingCloseHarnessScenariosWithFake(t *testing.T) {
	t.Run("C1", func(t *testing.T) {
		s := newFakeCCSigner(t)
		obs := runCCC1(ccOfflineConfig, ccTestFixture(t, s), s)
		waitLeftover(t, obs)
		v := verifyCC(obs)
		if v.Outcome != ccPass || v.Succeeded != ccOfflineConfig.C1Pairs || v.Failed != 1 {
			t.Fatalf("C1: %s", v)
		}
	})
	for _, c := range []struct {
		name string
		ver  uint16
	}{{"C2a", tls.VersionTLS13}, {"C2b", tls.VersionTLS12}} {
		t.Run(c.name, func(t *testing.T) {
			s := newFakeCCSigner(t)
			obs := runCCC2(ccOfflineConfig, ccTestFixture(t, s), s, c.name, c.ver)
			waitLeftover(t, obs)
			if v := verifyCC(obs); v.Outcome != ccPass || v.Failed != 1 {
				t.Fatalf("%s: %s", c.name, v)
			}
		})
	}
	t.Run("C3 round", func(t *testing.T) {
		s := newFakeCCSigner(t)
		obs := runCCC3Round(ccOfflineConfig, ccTestFixture(t, s), s, 1)
		waitLeftover(t, obs)
		v := verifyCC(obs)
		if v.Outcome != ccPass || v.Succeeded < ccOfflineConfig.C3Threshold || v.Failed < ccOfflineConfig.C3Workers {
			t.Fatalf("C3: %s", v)
		}
	})
	t.Run("all scenarios on one key", func(t *testing.T) {
		// Every handle of the same key shares the private key, as a reopened
		// CNG handle does.
		created := newFakeCCSigner(t)
		var opened []*fakeCCSigner
		open := func() (crypto.Signer, error) {
			s := &fakeCCSigner{key: created.key}
			opened = append(opened, s)
			return s, nil
		}
		out := runCCScenarios(ccOfflineConfig, time.Now(), created, open)
		if !out.Pass || !out.ReleaseConfirmed {
			for _, s := range out.Scenarios {
				t.Logf("%s: %s", s.Obs.Scenario, s.Verdict)
			}
			t.Fatalf("run: pass=%v release=%v notes=%v", out.Pass, out.ReleaseConfirmed, out.Notes)
		}
		if want := 1 + 2 + ccOfflineConfig.C3Rounds; len(out.Scenarios) != want || len(out.Handles) != want {
			t.Fatalf("scenarios=%d handles=%d, want %d", len(out.Scenarios), len(out.Handles), want)
		}
		for _, s := range append([]*fakeCCSigner{created}, opened...) {
			if s.closes.Load() != 2 {
				t.Fatalf("handle closed %d times, want 2 (Close1 and Close2)", s.closes.Load())
			}
		}
	})
}

// ---- runner with defective fakes: the specific rule must fire ----

func TestServingCloseHarnessDefectiveFakes(t *testing.T) {
	t.Run("Sign accepted after Close: C1 probe is R1", func(t *testing.T) {
		s := newFakeCCSigner(t)
		s.acceptAfterClose = true
		obs := runCCC1(ccOfflineConfig, ccTestFixture(t, s), s)
		waitLeftover(t, obs)
		v := verifyCC(obs)
		requireFinding(t, v, "R1", ccViolation)
		if v.Outcome != ccViolation {
			t.Fatalf("outcome %s", v.Outcome)
		}
	})
	t.Run("Sign accepted after Close: C2 is a violation", func(t *testing.T) {
		s := newFakeCCSigner(t)
		s.acceptAfterClose = true
		obs := runCCC2(ccOfflineConfig, ccTestFixture(t, s), s, "C2a", tls.VersionTLS13)
		waitLeftover(t, obs)
		requireFinding(t, verifyCC(obs), "C2", ccViolation)
	})
	t.Run("native failure before Close is R2", func(t *testing.T) {
		s := newFakeCCSigner(t)
		s.failSignAt = 3
		obs := runCCC1(ccOfflineConfig, ccTestFixture(t, s), s)
		waitLeftover(t, obs)
		v := verifyCC(obs)
		requireFinding(t, v, "R2", ccNonPositive)
		if !v.ReleaseConfirmed {
			t.Fatalf("release should be confirmed: %s", v)
		}
	})
	t.Run("first Close error is R6 even though the second returns nil", func(t *testing.T) {
		s := newFakeCCSigner(t)
		s.closeErr = errors.New("free failed")
		obs := runCCC1(ccOfflineConfig, ccTestFixture(t, s), s)
		waitLeftover(t, obs)
		v := verifyCC(obs)
		requireFinding(t, v, "R6", ccReleaseUnconfirmed)
		if v.ReleaseConfirmed || v.has("R7", ccNonPositive) {
			t.Fatalf("verdict: %s", v)
		}
	})
	t.Run("panic in Sign vetoes release", func(t *testing.T) {
		s := newFakeCCSigner(t)
		s.panicSignAt = 2
		obs := runCCC1(ccOfflineConfig, ccTestFixture(t, s), s)
		waitLeftover(t, obs)
		v := verifyCC(obs)
		requireFinding(t, v, "R8", ccReleaseUnconfirmed)
		if v.ReleaseConfirmed {
			t.Fatalf("verdict: %s", v)
		}
	})
	// The two blocked-Close cases keep the generous scenario watchdog for the
	// handshakes and restart a short one when Close starts (closeWatchdog), so
	// the timeout is driven only after the fault point; closeEntered proves
	// the blocked Close was actually reached.
	blockedClose := func(t *testing.T) (*fakeCCSigner, func()) {
		s := newFakeCCSigner(t)
		s.closeBlock = make(chan struct{})
		s.closeEntered = make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(s.closeBlock) }) }
		t.Cleanup(release) // released even if an assertion fails first
		return s, release
	}
	requireCloseEntered := func(t *testing.T, s *fakeCCSigner) {
		t.Helper()
		select {
		case <-s.closeEntered:
		default:
			t.Fatal("the blocked Close was never entered: the fault point was not exercised")
		}
	}
	t.Run("Close blocked, released after the decision: no quiescence", func(t *testing.T) {
		s, release := blockedClose(t)
		cfg := ccOfflineConfig
		cfg.C1Pairs = 2
		cfg.closeWatchdog = 300 * time.Millisecond
		cfg.Quiesce = 300 * time.Millisecond
		obs := runCCC1(cfg, ccTestFixture(t, s), s)
		v := verifyCC(obs)
		release()
		waitLeftover(t, obs)
		requireCloseEntered(t, s)
		requireFinding(t, v, "R8", ccReleaseUnconfirmed)
		requireFinding(t, v, "R6", ccReleaseUnconfirmed)
		requireFinding(t, v, "R8", ccNonPositive)
		if v.ReleaseConfirmed || obs.Stack == "" {
			t.Fatalf("verdict: %s (stack captured=%v)", v, obs.Stack != "")
		}
	})
	t.Run("Close blocked, released at the watchdog: quiescent but non-positive", func(t *testing.T) {
		s, release := blockedClose(t)
		cfg := ccOfflineConfig
		cfg.C1Pairs = 2
		cfg.closeWatchdog = 300 * time.Millisecond
		cfg.onWatchdog = release
		obs := runCCC1(cfg, ccTestFixture(t, s), s)
		waitLeftover(t, obs)
		requireCloseEntered(t, s)
		v := verifyCC(obs)
		requireFinding(t, v, "R8", ccNonPositive)
		if !obs.Quiescent || !v.ReleaseConfirmed || v.Outcome != ccNonPositive {
			t.Fatalf("quiescent=%v verdict: %s", obs.Quiescent, v)
		}
	})
}

// ---- live orchestration decisions with fake key operations ----

type fakeCCKeyOps struct {
	calls     []string
	nameErr   error
	diagErr   error
	openErrs  []error // per open call; nil entry means "opens"
	createErr error
	delErr    error
	preflight *fakeCCSigner
}

func (f *fakeCCKeyOps) ops(t *testing.T) ccKeyOps {
	return ccKeyOps{
		newName: func() (string, error) {
			f.calls = append(f.calls, "name")
			return "Keppin.Test.ServingClose.0011223344556677", f.nameErr
		},
		writeDiag: func(string) error { f.calls = append(f.calls, "diag"); return f.diagErr },
		open: func(string) (crypto.Signer, error) {
			f.calls = append(f.calls, "open")
			var err error
			if len(f.openErrs) > 0 {
				err, f.openErrs = f.openErrs[0], f.openErrs[1:]
			}
			if err != nil {
				return nil, err
			}
			f.preflight = newFakeCCSigner(t)
			return f.preflight, nil
		},
		create: func(string) (crypto.Signer, error) {
			f.calls = append(f.calls, "create")
			if f.createErr != nil {
				return nil, f.createErr
			}
			return newFakeCCSigner(t), nil
		},
		del: func(string) error { f.calls = append(f.calls, "delete"); return f.delErr },
	}
}

func fixedRun(out ccRunOutcome) ccRunner {
	return func(crypto.Signer, func() (crypto.Signer, error)) ccRunOutcome { return out }
}

func TestServingCloseHarnessCleanupDecisions(t *testing.T) {
	notFound := []error{ErrKeyNotFound}
	cases := []struct {
		name      string
		keys      fakeCCKeyOps
		run       ccRunOutcome
		calls     string
		pass      bool
		mayRemain bool
	}{
		{"name generation fails", fakeCCKeyOps{nameErr: errors.New("rng")}, ccRunOutcome{}, "name", false, false},
		{"diagnostics fail before create", fakeCCKeyOps{diagErr: errors.New("disk")}, ccRunOutcome{}, "name diag", false, false},
		{"preflight opens a key: closed, no create, no delete", fakeCCKeyOps{openErrs: []error{nil}}, ccRunOutcome{}, "name diag open", false, false},
		{"preflight other error stops", fakeCCKeyOps{openErrs: []error{errors.New("provider")}}, ccRunOutcome{}, "name diag open", false, false},
		{"create fails (cleanup failed): no delete", fakeCCKeyOps{openErrs: notFound, createErr: errors.New("create: cleanup failed")}, ccRunOutcome{}, "name diag open create", false, true},
		{"release not confirmed: no delete", fakeCCKeyOps{openErrs: notFound}, ccRunOutcome{Pass: false, ReleaseConfirmed: false}, "name diag open create", false, true},
		{"ownership lost (public key mismatch) with confirmed release: no delete", fakeCCKeyOps{openErrs: notFound}, ccRunOutcome{Pass: false, ReleaseConfirmed: true, OwnershipLost: true}, "name diag open create", false, true},
		{"non-positive run with confirmed release: single delete, FAIL", fakeCCKeyOps{openErrs: notFound}, ccRunOutcome{Pass: false, ReleaseConfirmed: true}, "name diag open create delete", false, false},
		{"delete fails with not found: one attempt, unconfirmed", fakeCCKeyOps{openErrs: notFound, delErr: ErrKeyNotFound}, ccRunOutcome{Pass: true, ReleaseConfirmed: true}, "name diag open create delete", false, true},
		{"all conforming: single delete, PASS", fakeCCKeyOps{openErrs: notFound}, ccRunOutcome{Pass: true, ReleaseConfirmed: true}, "name diag open create delete", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keys := c.keys
			rep := executeServingClose(keys.ops(t), fixedRun(c.run), t.Logf)
			if got := strings.Join(keys.calls, " "); got != c.calls {
				t.Fatalf("calls = %q, want %q (stage: %s)", got, c.calls, rep.Stage)
			}
			if rep.Pass != c.pass || rep.KeyMayRemain != c.mayRemain {
				t.Fatalf("pass=%v mayRemain=%v, want %v %v (stage: %s)", rep.Pass, rep.KeyMayRemain, c.pass, c.mayRemain, rep.Stage)
			}
			if keys.preflight != nil && keys.preflight.closes.Load() != 1 {
				t.Fatalf("preflight handle closed %d times, want 1", keys.preflight.closes.Load())
			}
		})
	}
}

func TestServingCloseHarnessDiagnosticsAndName(t *testing.T) {
	name, err := newServingCloseKeyName()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^Keppin\.Test\.ServingClose\.[0-9a-f]{16}$`).MatchString(name) {
		t.Fatalf("key name %q", name)
	}
	dir := t.TempDir()
	if err := writeServingCloseDiag(dir, name); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("diag entries=%d err=%v", len(entries), err)
	}
	got, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil || string(got) != "key="+name+"\n" {
		t.Fatalf("diag content %q err=%v", got, err)
	}
	if err := writeServingCloseDiag(filepath.Join(dir, "missing"), name); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
}

// ---- coordinator deadline, diagnostics and handle inventory ----

func TestServingCloseHarnessAwaitDeadlineAlreadyPassed(t *testing.T) {
	ready := make(chan struct{})
	close(ready)

	c := newCCCoordinator(ccOfflineConfig, -time.Second) // deadline already passed
	if c.await(ready) {
		t.Fatal("await accepted a completion after the deadline")
	}
	if !c.fired {
		t.Fatal("watchdog not recorded")
	}
	if c.await(ready) {
		t.Fatal("await accepted a completion after the watchdog fired")
	}

	c = newCCCoordinator(ccOfflineConfig, time.Minute)
	if !c.await(ready) || c.fired {
		t.Fatal("a completion before the deadline was rejected")
	}
}

func TestServingCloseHarnessDiagnosticLines(t *testing.T) {
	b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccGateArrive, 0, true).close1(true).
		ev(ccGateRelease, 0, true).ev(ccSignReturn, 0, false).close2(true)
	p := failedPair(0)
	p.ServerErr = errors.New("server-original-error")
	o := ccObs(b, p)
	o.Scenario = "C2a"
	got := strings.Join(ccDiagnosticLines(o), "\n")
	for _, want := range []string{
		"C2a: Sign failed conn=0 callSeq=1 returnSeq=6 err=synthetic",
		"C2a: GateArrive seq=2 conn=0",
		"C2a: Close1Return seq=4 err=<nil>",
		"C2a: GateRelease seq=5 conn=0",
		"C2a: pair 0",
		"server err=server-original-error",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnostic lines miss %q:\n%s", want, got)
		}
	}
}

func TestServingCloseHarnessHandleRegisteredOnAcquisition(t *testing.T) {
	created := newFakeCCSigner(t)
	var wrong *fakeCCSigner
	open := func() (crypto.Signer, error) {
		wrong = newFakeCCSigner(t) // another key: public key mismatch
		return wrong, nil
	}
	out := runCCScenarios(ccOfflineConfig, time.Now(), created, open)
	if out.Pass {
		t.Fatal("run with a mismatched handle passed")
	}
	if len(out.Handles) != 2 || out.Handles[0].Label != "create/C1" || out.Handles[1].Label != "C2a" {
		t.Fatalf("handles: %+v", out.Handles)
	}
	if !out.Handles[1].Closed || out.Handles[1].CloseErr != nil || wrong.closes.Load() != 1 {
		t.Fatalf("mismatched handle not closed once: %+v closes=%d", out.Handles[1], wrong.closes.Load())
	}
	// The handles are released, but the key under the name is not proven to
	// be the created one: ownership is lost, which alone vetoes the Delete.
	if !out.ReleaseConfirmed || !out.OwnershipLost {
		t.Fatalf("release=%v ownershipLost=%v, want true true: %+v", out.ReleaseConfirmed, out.OwnershipLost, out.Handles)
	}
}

// The deadline check after the select: the completion is ready and the timer
// is far away, but the coordinator clock observes it past the deadline.
func TestServingCloseHarnessAwaitCompletionObservedAfterDeadline(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	c := newCCCoordinator(ccOfflineConfig, time.Minute)
	deadline := c.deadline
	calls := 0
	c.now = func() time.Time {
		calls++
		if calls == 1 {
			return deadline.Add(-time.Second) // on entry: before the deadline
		}
		return deadline.Add(time.Second) // after the select: past it
	}
	if c.await(ready) {
		t.Fatal("await accepted a completion observed after the deadline")
	}
	if !c.fired || calls != 2 {
		t.Fatalf("fired=%v clock calls=%d, want true 2", c.fired, calls)
	}
}

// A C2 pair that fails before reaching the gate is not a hang: no watchdog,
// the handle is closed, release is confirmed, and the verdict reports the
// missing gate order and the pair that never signed.
func TestServingCloseHarnessC2PairEndsBeforeGate(t *testing.T) {
	good := newFakeCCSigner(t)
	fx := ccTestFixture(t, good)
	odd := newFakeCCSigner(t)
	odd.publicOverride = struct{}{} // crypto/tls cannot pick a signature scheme
	obs := runCCC2(ccOfflineConfig, fx, odd, "C2a", tls.VersionTLS13)
	waitLeftover(t, obs)
	v := verifyCC(obs)
	if obs.WatchdogFired || !obs.Quiescent || !v.ReleaseConfirmed || v.Outcome != ccNonPositive {
		t.Fatalf("watchdog=%v quiescent=%v verdict: %s", obs.WatchdogFired, obs.Quiescent, v)
	}
	requireFinding(t, v, "C2", ccNonPositive)
	requireFinding(t, v, "R5", ccNonPositive)
	if odd.closes.Load() != 2 || odd.signs.Load() != 0 {
		t.Fatalf("closes=%d signs=%d, want 2 0", odd.closes.Load(), odd.signs.Load())
	}
}

func TestServingCloseHarnessLiveConfigHasNoTestSeams(t *testing.T) {
	if ccLiveConfig.onWatchdog != nil || ccLiveConfig.closeWatchdog != 0 {
		t.Fatal("test seams are set in the live configuration")
	}
	c := ccLiveConfig
	if c.PipeDeadline != 10*time.Second || c.Watchdog != 30*time.Second || c.RoundWatchdog != 60*time.Second ||
		c.Quiesce != 10*time.Second || c.C1Pairs != 32 || c.C3Workers != 8 || c.C3Threshold != 50 || c.C3Rounds != 20 {
		t.Fatalf("live configuration differs from the expected values: %+v", c)
	}
}

func TestServingCloseHarnessDiagnosticLinesGatedSuccess(t *testing.T) {
	b := (&ccTraceBuilder{}).ev(ccSignCall, 0, true).ev(ccGateArrive, 0, true).close1(true).
		ev(ccGateRelease, 0, true).ev(ccSignReturn, 0, true).close2(true)
	o := ccObs(b, okPair(0))
	o.Scenario = "C2b"
	o.Gate = &ccGateExpectation{Conn: 0}
	got := strings.Join(ccDiagnosticLines(o), "\n")
	if !strings.Contains(got, "C2b: gated Sign succeeded conn=0 callSeq=1 returnSeq=6") {
		t.Fatalf("gated success not logged:\n%s", got)
	}
}
