package localtls

// Serving-close harness: TLS handshakes concurrent with Material.Close.
//
// The harness wraps the serving signer in an observedSigner that numbers
// every Sign and Close event with an atomic sequence, runs TLS handshakes over
// net.Pipe against an in-memory CA (no LocalMachine\Root, no files), and hands
// the resulting trace to a pure verifier (verifyCC). The sequences classify
// windows observed by the wrapper; they are not the order of the lock inside
// the signer. Errors are kept for diagnostics only and never parsed.
//
// The live test (TestServingCloseRaceElevated, Windows only) drives the same
// scenarios with a real CNG test key; the offline tests drive them with an
// in-memory fake and table-test the verifier and the cleanup decisions.
//
// Scenarios, as named in the verdicts and in the log:
//
//	C1     consumer drain: concurrent handshakes all complete, then
//	       Material.Close, then a probe handshake that must fail
//	C2a/b  deterministic race (TLS 1.3 / TLS 1.2): a handshake is held before
//	       signing while Material.Close runs and returns, then released; its
//	       signature must fail
//	C3/NN  stress round NN: workers loop handshakes while Material.Close runs
//
// The verifier rules R1-R8, C2 and S are listed at verifyCC.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keppin-oss/local-tls/internal/identity"
)

// ---- trace ----

type ccEventKind int

const (
	ccSignCall ccEventKind = iota + 1
	ccSignReturn
	ccClose1Call
	ccClose1Return
	ccClose2Call
	ccClose2Return
	ccGateArrive
	ccGateRelease
)

func (k ccEventKind) String() string {
	switch k {
	case ccSignCall:
		return "SignCall"
	case ccSignReturn:
		return "SignReturn"
	case ccClose1Call:
		return "Close1Call"
	case ccClose1Return:
		return "Close1Return"
	case ccClose2Call:
		return "Close2Call"
	case ccClose2Return:
		return "Close2Return"
	case ccGateArrive:
		return "GateArrive"
	case ccGateRelease:
		return "GateRelease"
	}
	return fmt.Sprintf("event(%d)", int(k))
}

// ccNoConn marks events that do not belong to a connection (Close events, or a
// Sign called directly on the observed signer instead of a connection view).
const ccNoConn = -1

type ccEvent struct {
	Seq  uint64
	Kind ccEventKind
	Conn int
	OK   bool  // for *Return events: the call returned a nil error
	Err  error // diagnostics only, never used as an oracle
}

// ccTrace records events. The sequence number is taken atomically when the
// event happens; the mutex only protects the append and is never held while
// the wrapped signer runs.
type ccTrace struct {
	seq    atomic.Uint64
	mu     sync.Mutex
	events []ccEvent
}

func (t *ccTrace) record(kind ccEventKind, conn int, err error) {
	s := t.seq.Add(1)
	t.mu.Lock()
	t.events = append(t.events, ccEvent{Seq: s, Kind: kind, Conn: conn, OK: err == nil, Err: err})
	t.mu.Unlock()
}

func (t *ccTrace) snapshot() []ccEvent {
	t.mu.Lock()
	out := append([]ccEvent(nil), t.events...)
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// ---- observed signer and per-connection views ----

// observedSigner wraps the serving signer. It adds no lock between Sign and
// Close: the concurrency under test is the wrapped signer's own. The first
// Close and every later Close are recorded as distinct events.
type observedSigner struct {
	inner  crypto.Signer
	trace  *ccTrace
	gate   func(conn int) // optional; runs after SignCall, before delegating
	closes atomic.Int32
}

func (o *observedSigner) Public() crypto.PublicKey { return o.inner.Public() }

func (o *observedSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.signFor(ccNoConn, r, digest, opts)
}

func (o *observedSigner) signFor(conn int, r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	o.trace.record(ccSignCall, conn, nil)
	if o.gate != nil {
		o.gate(conn)
	}
	sig, err := o.inner.Sign(r, digest, opts)
	o.trace.record(ccSignReturn, conn, err)
	return sig, err
}

// Close is what Material.Close reaches through closeSigner.
func (o *observedSigner) Close() error {
	callKind, retKind := ccClose1Call, ccClose1Return
	if o.closes.Add(1) > 1 {
		callKind, retKind = ccClose2Call, ccClose2Return
	}
	o.trace.record(callKind, ccNoConn, nil)
	err := closeSigner(o.inner)
	o.trace.record(retKind, ccNoConn, err)
	return err
}

// connSignerView is the immutable per-connection private key handed to the
// server of one pair. It delegates to the shared observedSigner (the one
// Material.Close closes) and has no Close of its own.
type connSignerView struct {
	id int
	o  *observedSigner
}

func (v connSignerView) Public() crypto.PublicKey { return v.o.Public() }

func (v connSignerView) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return v.o.signFor(v.id, r, digest, opts)
}

// ---- fixture ----

// ccFixture is the in-memory CA and the leaf for the serving key. It is built
// once per run; every reopened handle is checked against the leaf.
type ccFixture struct {
	ca      *x509.Certificate
	leaf    *x509.Certificate
	leafSHA [32]byte
}

func newCCFixture(now time.Time, server crypto.Signer) (*ccFixture, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate in-memory CA key: %w", err)
	}
	ca, err := generateCAWithSigner(now, caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := generateServerCertWithSigner(now, ca, caKey, server)
	if err != nil {
		return nil, err
	}
	return &ccFixture{ca: ca, leaf: leaf, leafSHA: sha256.Sum256(leaf.Raw)}, nil
}

// ---- one handshake pair ----

type ccPairResult struct {
	ID            int
	Version       uint16
	ServerErr     error
	ClientErr     error
	ServerTimeout bool // typed: net.Error with Timeout()
	ClientTimeout bool
	Canceled      bool // the coordinator canceled the scenario
	Panic         string
	CheckErr      error // verification of a handshake that succeeded on both sides
}

func (r ccPairResult) succeeded() bool {
	return r.ServerErr == nil && r.ClientErr == nil && r.Panic == ""
}

func (r ccPairResult) verified() bool { return r.succeeded() && r.CheckErr == nil }

func ccIsTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// runCCPair performs one fresh, full handshake over net.Pipe. The server uses
// its own config and certificate copy whose private key is the view for id.
func runCCPair(ctx context.Context, fx *ccFixture, o *observedSigner, id int, version uint16, pipeDeadline time.Duration) ccPairResult {
	res := ccPairResult{ID: id, Version: version}
	srvConn, cliConn := net.Pipe()
	dl := time.Now().Add(pipeDeadline)
	_ = srvConn.SetDeadline(dl)
	_ = cliConn.SetDeadline(dl)

	// Cancellation closes both endpoints, which unblocks pipe I/O.
	stop := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			_ = srvConn.Close()
			_ = cliConn.Close()
		case <-stop:
		}
	}()

	cert := tls.Certificate{
		Certificate: [][]byte{fx.leaf.Raw},
		PrivateKey:  connSignerView{id: id, o: o},
		Leaf:        fx.leaf,
	}
	srvCfg := &tls.Config{
		MinVersion:             version,
		MaxVersion:             version,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{cert},
	}
	roots := x509.NewCertPool()
	roots.AddCert(fx.ca)
	cliCfg := &tls.Config{
		MinVersion:             version,
		MaxVersion:             version,
		RootCAs:                roots,
		ServerName:             "localhost",
		SessionTicketsDisabled: true,
	}

	var srvErr error
	var srvPanic string
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		defer func() { _ = srvConn.Close() }()
		defer func() {
			if p := recover(); p != nil {
				srvPanic = fmt.Sprintf("server: %v", p)
			}
		}()
		srvErr = tls.Server(srvConn, srvCfg).Handshake()
	}()

	var state tls.ConnectionState
	var cliPanic string
	func() {
		defer func() { _ = cliConn.Close() }()
		defer func() {
			if p := recover(); p != nil {
				cliPanic = fmt.Sprintf("client: %v", p)
			}
		}()
		c := tls.Client(cliConn, cliCfg)
		res.ClientErr = c.Handshake()
		if res.ClientErr == nil {
			state = c.ConnectionState()
		}
	}()
	<-srvDone
	close(stop)
	<-watchDone

	res.ServerErr = srvErr
	res.Panic = strings.TrimSpace(srvPanic + " " + cliPanic)
	if res.Panic != "" {
		// A panicking side has no meaningful handshake error of its own.
		if srvPanic != "" && res.ServerErr == nil {
			res.ServerErr = errors.New(srvPanic)
		}
		if cliPanic != "" && res.ClientErr == nil {
			res.ClientErr = errors.New(cliPanic)
		}
	}
	res.ServerTimeout = ccIsTimeout(res.ServerErr)
	res.ClientTimeout = ccIsTimeout(res.ClientErr)
	res.Canceled = ctx.Err() != nil
	if res.succeeded() {
		res.CheckErr = checkCCClientState(state, fx, version)
	}
	return res
}

// checkCCClientState verifies what the client observed: negotiated version,
// hostname, a chain verified to the in-memory CA, the expected leaf and a
// full (not resumed) handshake.
func checkCCClientState(st tls.ConnectionState, fx *ccFixture, version uint16) error {
	var errs []error
	if !st.HandshakeComplete {
		errs = append(errs, errors.New("handshake not complete"))
	}
	if st.Version != version {
		errs = append(errs, fmt.Errorf("negotiated version 0x%04x, want 0x%04x", st.Version, version))
	}
	if st.DidResume {
		errs = append(errs, errors.New("handshake resumed"))
	}
	if st.ServerName != "localhost" {
		errs = append(errs, fmt.Errorf("server name %q, want %q", st.ServerName, "localhost"))
	}
	if len(st.PeerCertificates) == 0 {
		errs = append(errs, errors.New("no peer certificate"))
	} else if sha256.Sum256(st.PeerCertificates[0].Raw) != fx.leafSHA {
		errs = append(errs, errors.New("peer leaf SHA-256 differs from the expected leaf"))
	}
	chainOK := false
	for _, ch := range st.VerifiedChains {
		if len(ch) >= 2 && ch[0].Equal(fx.leaf) && ch[len(ch)-1].Equal(fx.ca) {
			chainOK = true
			break
		}
	}
	if !chainOK {
		errs = append(errs, errors.New("no verified chain from the expected leaf to the in-memory CA"))
	}
	return errors.Join(errs...)
}

// ---- observation, findings and verdict ----

type ccGateExpectation struct{ Conn int }

type ccScenarioKind int

const (
	ccKindC1 ccScenarioKind = iota + 1
	ccKindC2
	ccKindC3
)

// ccExpect is the evidence a scenario must produce. Without it the verifier
// only checks the records present; with it, missing evidence is not a PASS.
type ccExpect struct {
	Kind         ccScenarioKind
	DrainedPairs int // C1: pairs 0..DrainedPairs-1 verified, all before Close1
	ProbeID      int // C1: the probe pair, failed with its own POST Sign failed
	GateConn     int // C2: the only pair
	MinVerified  int // C3: verified pairs that triggered Close1
	PostPairs    int // C3: pairs whose own Sign is POST and failed (one per worker)
}

// ccObservation is everything the verifier needs about one scenario run.
type ccObservation struct {
	Scenario      string
	Events        []ccEvent
	Pairs         []ccPairResult
	Expect        *ccExpect
	ExpectClose2  bool
	Gate          *ccGateExpectation // C2 only
	WatchdogFired bool
	Quiescent     bool
	Panics        []string
	Stack         string // goroutine dump taken when the watchdog fired

	// leftover is closed once every goroutine of the scenario has returned.
	// It is a test seam for releasing blocked fakes; the verifier ignores it.
	leftover <-chan struct{}
}

type ccOutcome int

// Ordered by precedence for the summary: a higher value wins.
const (
	ccPass ccOutcome = iota
	ccNonPositive
	ccReleaseUnconfirmed
	ccViolation
)

func (o ccOutcome) String() string {
	switch o {
	case ccPass:
		return "PASS"
	case ccNonPositive:
		return "NON_POSITIVE"
	case ccReleaseUnconfirmed:
		return "RELEASE_UNCONFIRMED"
	case ccViolation:
		return "VIOLATION"
	}
	return fmt.Sprintf("outcome(%d)", int(o))
}

type ccFinding struct {
	Rule    string
	Outcome ccOutcome
	Detail  string
}

// ccVerdict keeps every finding. Outcome is only a summary chosen by
// precedence; the Delete decision uses ReleaseConfirmed, never Outcome.
type ccVerdict struct {
	Outcome          ccOutcome
	Findings         []ccFinding
	ReleaseConfirmed bool
	Succeeded        int
	Failed           int
	Overlapping      int // Sign calls overlapping Close1 as seen by the wrapper
	OverlapFailed    int // of which failed: compatible with Close, cause not discriminated
}

func (v ccVerdict) has(rule string, out ccOutcome) bool {
	for _, f := range v.Findings {
		if f.Rule == rule && f.Outcome == out {
			return true
		}
	}
	return false
}

func (v ccVerdict) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (release confirmed=%v; pairs succeeded=%d failed=%d; Sign calls overlapping Close as seen by the wrapper=%d, of which failed=%d)",
		v.Outcome, v.ReleaseConfirmed, v.Succeeded, v.Failed, v.Overlapping, v.OverlapFailed)
	for _, f := range v.Findings {
		fmt.Fprintf(&b, "\n  %s %s: %s", f.Rule, f.Outcome, f.Detail)
	}
	return b.String()
}

type ccSignState int

const (
	ccSignIncomplete ccSignState = iota
	ccSignPre
	ccSignOverlapping
	ccSignPost
)

func (s ccSignState) String() string {
	switch s {
	case ccSignPre:
		return "PRE"
	case ccSignOverlapping:
		return "OVERLAPPING"
	case ccSignPost:
		return "POST"
	}
	return "INCOMPLETE"
}

type ccSignRec struct {
	call, ret *ccEvent
}

// verifyCC is the pure verifier. It classifies windows observed by the wrapper
// and compatibility with the signer contract; it does not attribute a cause to
// overlapping failures and never reads error text.
//
// A Sign is PRE when it returned before Close1Call (or Close1 is absent), POST
// when it was called after Close1Return, OVERLAPPING otherwise. Rules:
//
//	R1 every POST Sign fails                                -> VIOLATION
//	R2 every PRE Sign succeeds                              -> NON_POSITIVE
//	R3 an OVERLAPPING Sign may succeed or fail              (counted only)
//	R4 a successful pair passes the client verification
//	   and has a successful Sign on its own connection      -> NON_POSITIVE
//	R5 a failed pair failed on both sides, without timeout
//	   or cancellation, and its own Sign is OVERLAPPING or
//	   POST and failed; every Sign belongs to a known pair  -> NON_POSITIVE
//	R6 Close1 returned nil                                  -> RELEASE_UNCONFIRMED
//	R7 Close2 returned nil when expected                    -> NON_POSITIVE
//	R8 quiescence, no panic, no Sign without return         -> RELEASE_UNCONFIRMED
//	   watchdog expired                                     -> NON_POSITIVE
//	C2 gate arrival < Close1Call, Close1Return < release
//	   < return of the gated Sign; that Sign fails          -> NON_POSITIVE / VIOLATION
//	S  the evidence declared in obs.Expect is present       -> NON_POSITIVE
//
// Each pair id must be unique and each connection signs at most once (one
// full handshake per pair, one signature per handshake in this setup);
// otherwise R5 -> NON_POSITIVE, because Sign-to-pair association is lost.
func verifyCC(obs ccObservation) ccVerdict {
	var v ccVerdict
	add := func(rule string, out ccOutcome, format string, args ...any) {
		v.Findings = append(v.Findings, ccFinding{Rule: rule, Outcome: out, Detail: fmt.Sprintf(format, args...)})
	}

	var c1Call, c1Ret, c2Ret *ccEvent
	gateArrive := map[int]*ccEvent{}
	gateRelease := map[int]*ccEvent{}
	signs := map[int][]*ccSignRec{}
	var signConns []int
	for i := range obs.Events {
		e := &obs.Events[i]
		switch e.Kind {
		case ccSignCall:
			if _, seen := signs[e.Conn]; !seen {
				signConns = append(signConns, e.Conn)
			}
			signs[e.Conn] = append(signs[e.Conn], &ccSignRec{call: e})
		case ccSignReturn:
			matched := false
			for _, r := range signs[e.Conn] {
				if r.ret == nil {
					r.ret = e
					matched = true
					break
				}
			}
			if !matched {
				add("R8", ccNonPositive, "SignReturn seq=%d conn=%d without a matching SignCall", e.Seq, e.Conn)
			}
		case ccClose1Call:
			if c1Call == nil {
				c1Call = e
			}
		case ccClose1Return:
			if c1Ret == nil {
				c1Ret = e
			}
		case ccClose2Return:
			if c2Ret == nil {
				c2Ret = e
			}
		case ccGateArrive:
			if gateArrive[e.Conn] == nil {
				gateArrive[e.Conn] = e
			}
		case ccGateRelease:
			if gateRelease[e.Conn] == nil {
				gateRelease[e.Conn] = e
			}
		}
	}

	state := func(r *ccSignRec) ccSignState {
		switch {
		case r.ret == nil:
			return ccSignIncomplete
		case c1Call == nil || r.ret.Seq < c1Call.Seq:
			return ccSignPre
		case c1Ret != nil && r.call.Seq > c1Ret.Seq:
			return ccSignPost
		default:
			return ccSignOverlapping
		}
	}

	pairs := map[int]ccPairResult{}
	for _, p := range obs.Pairs {
		if _, dup := pairs[p.ID]; dup {
			add("R5", ccNonPositive, "duplicate pair id %d: results cannot be associated", p.ID)
			continue
		}
		pairs[p.ID] = p
	}

	// Sign rules (R1, R2, R3, R8 incomplete, R5 unknown connection).
	for _, conn := range signConns {
		if _, ok := pairs[conn]; !ok {
			add("R5", ccNonPositive, "Sign on connection id %d that belongs to no pair", conn)
		}
		if n := len(signs[conn]); n > 1 {
			add("R5", ccNonPositive, "connection id %d has %d Sign calls, expected at most one per handshake", conn, n)
		}
		for _, r := range signs[conn] {
			switch st := state(r); st {
			case ccSignIncomplete:
				add("R8", ccReleaseUnconfirmed, "Sign seq=%d conn=%d has no return", r.call.Seq, conn)
			case ccSignPre:
				if !r.ret.OK {
					add("R2", ccNonPositive, "PRE Sign seq=%d conn=%d failed (cause not discriminated): %v", r.call.Seq, conn, r.ret.Err)
				}
			case ccSignPost:
				if r.ret.OK {
					add("R1", ccViolation, "Sign called after Close1Return (seq=%d > %d) on conn=%d succeeded", r.call.Seq, c1Ret.Seq, conn)
				}
			case ccSignOverlapping:
				v.Overlapping++
				if !r.ret.OK {
					v.OverlapFailed++
				}
			}
		}
	}

	// Pair rules (R4, R5, R8 panic).
	ids := make([]int, 0, len(pairs))
	for id := range pairs {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		p := pairs[id]
		recs := signs[id]
		if p.Panic != "" {
			add("R8", ccReleaseUnconfirmed, "pair %d panicked: %s", id, p.Panic)
		}
		if p.succeeded() {
			v.Succeeded++
			if p.CheckErr != nil {
				add("R4", ccNonPositive, "pair %d succeeded but failed client verification: %v", id, p.CheckErr)
			}
			signedOK := false
			for _, r := range recs {
				if r.ret != nil && r.ret.OK {
					signedOK = true
				}
			}
			if !signedOK {
				add("R4", ccNonPositive, "pair %d succeeded without a successful Sign on its connection", id)
			}
			continue
		}
		v.Failed++
		switch {
		case p.ServerTimeout || p.ClientTimeout || p.Canceled:
			add("R5", ccNonPositive, "pair %d failed by timeout or cancellation (server=%v client=%v canceled=%v)", id, p.ServerTimeout, p.ClientTimeout, p.Canceled)
		case p.ServerErr == nil || p.ClientErr == nil:
			add("R5", ccNonPositive, "pair %d failed on one side only (server err=%v, client err=%v)", id, p.ServerErr, p.ClientErr)
		case len(recs) == 0:
			add("R5", ccNonPositive, "pair %d failed without reaching Sign (server err=%v)", id, p.ServerErr)
		default:
			ownFailed := false
			for _, r := range recs {
				st := state(r)
				if r.ret != nil && !r.ret.OK && (st == ccSignOverlapping || st == ccSignPost) {
					ownFailed = true
				}
			}
			if !ownFailed {
				add("R5", ccNonPositive, "pair %d failed but its own Sign did not fail OVERLAPPING or POST", id)
			}
		}
	}

	// C2: the gated Sign is ordered after Close1Return by construction.
	if obs.Gate != nil {
		conn := obs.Gate.Conn
		arrive, release := gateArrive[conn], gateRelease[conn]
		var rec *ccSignRec
		if rs := signs[conn]; len(rs) == 1 {
			rec = rs[0]
		}
		orderOK := arrive != nil && release != nil && c1Call != nil && c1Ret != nil && rec != nil && rec.ret != nil &&
			arrive.Seq < c1Call.Seq && c1Ret.Seq < release.Seq && release.Seq < rec.ret.Seq
		switch {
		case !orderOK:
			add("C2", ccNonPositive, "order gate arrival < Close1Call, Close1Return < release < Sign return not proven for conn=%d", conn)
		case rec.ret.OK:
			add("C2", ccViolation, "gated Sign released after Close1Return succeeded on conn=%d", conn)
		}
	}

	// S: scenario evidence.
	if ex := obs.Expect; ex != nil {
		postFailed := func(id int) bool {
			for _, r := range signs[id] {
				if state(r) == ccSignPost && !r.ret.OK {
					return true
				}
			}
			return false
		}
		switch ex.Kind {
		case ccKindC1:
			for id := 0; id < ex.DrainedPairs; id++ {
				p, ok := pairs[id]
				if !ok || !p.verified() {
					add("S", ccNonPositive, "C1: drained pair %d missing or not verified", id)
					continue
				}
				for _, r := range signs[id] {
					if state(r) != ccSignPre {
						add("S", ccNonPositive, "C1: drained pair %d signed %s, want PRE", id, state(r))
					}
				}
			}
			if p, ok := pairs[ex.ProbeID]; !ok || p.succeeded() || !postFailed(ex.ProbeID) {
				add("S", ccNonPositive, "C1: probe pair %d missing, succeeded, or without its own failed POST Sign", ex.ProbeID)
			}
			if want := ex.DrainedPairs + 1; len(obs.Pairs) != want {
				add("S", ccNonPositive, "C1: %d pair results, want %d", len(obs.Pairs), want)
			}
		case ccKindC2:
			if _, ok := pairs[ex.GateConn]; !ok || len(obs.Pairs) != 1 {
				add("S", ccNonPositive, "C2: want exactly the gated pair %d, got %d pair results", ex.GateConn, len(obs.Pairs))
			}
		case ccKindC3:
			// Counting pairs stands for counting workers: each worker leaves
			// only after one pair started once Close1 had returned (so its
			// Sign is POST), and the runner reaches Close2 only after every
			// worker has left.
			verified, post := 0, 0
			for _, id := range ids {
				if pairs[id].verified() {
					verified++
				}
				if !pairs[id].succeeded() && postFailed(id) {
					post++
				}
			}
			if verified < ex.MinVerified {
				add("S", ccNonPositive, "C3: %d verified pairs, want at least %d", verified, ex.MinVerified)
			}
			if post < ex.PostPairs {
				add("S", ccNonPositive, "C3: %d failed pairs with a POST Sign, want at least %d (one per worker)", post, ex.PostPairs)
			}
		}
	}

	// Close rules.
	switch {
	case c1Ret == nil:
		add("R6", ccReleaseUnconfirmed, "Close1 did not return (pending or never called)")
	case !c1Ret.OK:
		add("R6", ccReleaseUnconfirmed, "Close1 returned an error: %v", c1Ret.Err)
	}
	if obs.ExpectClose2 {
		switch {
		case c2Ret == nil:
			add("R7", ccNonPositive, "Close2 did not return (pending or never called)")
		case !c2Ret.OK:
			add("R7", ccNonPositive, "Close2 returned an error: %v", c2Ret.Err)
		}
	}

	// Termination rules.
	if !obs.Quiescent {
		add("R8", ccReleaseUnconfirmed, "scenario did not reach quiescence")
	}
	for _, p := range obs.Panics {
		add("R8", ccReleaseUnconfirmed, "panic: %s", p)
	}
	if obs.WatchdogFired {
		add("R8", ccNonPositive, "watchdog expired")
	}

	v.ReleaseConfirmed = true
	for _, f := range v.Findings {
		if f.Outcome > v.Outcome {
			v.Outcome = f.Outcome
		}
		if f.Outcome == ccReleaseUnconfirmed {
			v.ReleaseConfirmed = false
		}
	}
	return v
}

// ccDiagnosticLines lists, for the log, the evidence behind a verdict: the
// Close and gate events, every failed Sign and every failed pair with their
// original errors. It is diagnostics only: the verifier never reads it.
func ccDiagnosticLines(obs ccObservation) []string {
	var lines []string
	callSeq := map[int][]uint64{}
	for _, e := range obs.Events {
		switch e.Kind {
		case ccSignCall:
			callSeq[e.Conn] = append(callSeq[e.Conn], e.Seq)
		case ccSignReturn:
			call := uint64(0)
			if q := callSeq[e.Conn]; len(q) > 0 {
				call, callSeq[e.Conn] = q[0], q[1:]
			}
			if !e.OK {
				lines = append(lines, fmt.Sprintf("%s: Sign failed conn=%d callSeq=%d returnSeq=%d err=%v", obs.Scenario, e.Conn, call, e.Seq, e.Err))
			} else if obs.Gate != nil && e.Conn == obs.Gate.Conn {
				// The gated Sign is always logged: a success is the C2 violation.
				lines = append(lines, fmt.Sprintf("%s: gated Sign succeeded conn=%d callSeq=%d returnSeq=%d", obs.Scenario, e.Conn, call, e.Seq))
			}
		case ccClose1Call, ccClose2Call, ccGateArrive, ccGateRelease:
			lines = append(lines, fmt.Sprintf("%s: %s seq=%d conn=%d", obs.Scenario, e.Kind, e.Seq, e.Conn))
		case ccClose1Return, ccClose2Return:
			lines = append(lines, fmt.Sprintf("%s: %s seq=%d err=%v", obs.Scenario, e.Kind, e.Seq, e.Err))
		}
	}
	for _, p := range obs.Pairs {
		if p.succeeded() && p.CheckErr == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: pair %d version=0x%04x server err=%v client err=%v timeout(server=%v client=%v) canceled=%v panic=%q check=%v",
			obs.Scenario, p.ID, p.Version, p.ServerErr, p.ClientErr, p.ServerTimeout, p.ClientTimeout, p.Canceled, p.Panic, p.CheckErr))
	}
	return lines
}

// ---- coordinator and scenarios ----

type ccConfig struct {
	PipeDeadline  time.Duration // I/O only
	Watchdog      time.Duration // C1, and each C2
	RoundWatchdog time.Duration // each C3 round
	Quiesce       time.Duration
	C1Pairs       int
	C3Workers     int
	C3Threshold   int
	C3Rounds      int

	onWatchdog    func()        // test seam, called when the watchdog fires
	closeWatchdog time.Duration // test seam, zero in the live configuration
}

var ccLiveConfig = ccConfig{
	PipeDeadline:  10 * time.Second,
	Watchdog:      30 * time.Second,
	RoundWatchdog: 60 * time.Second,
	Quiesce:       10 * time.Second,
	C1Pairs:       32,
	C3Workers:     8,
	C3Threshold:   50,
	C3Rounds:      20,
}

// ccCoordinator is the single owner of one scenario: it tracks every
// goroutine, collects results, enforces the watchdog and, on every path,
// cancels, releases gates and waits a bounded time for quiescence.
type ccCoordinator struct {
	cfg      ccConfig
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
	now      func() time.Time // the coordinator clock; time.Now except in tests
	wg       sync.WaitGroup

	mu       sync.Mutex
	pairs    []ccPairResult
	panics   []string
	fired    bool
	stack    string
	releases []func()
}

func newCCCoordinator(cfg ccConfig, watchdog time.Duration) *ccCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &ccCoordinator{cfg: cfg, ctx: ctx, cancel: cancel, deadline: time.Now().Add(watchdog), now: time.Now}
}

func (c *ccCoordinator) addPair(r ccPairResult) {
	c.mu.Lock()
	c.pairs = append(c.pairs, r)
	c.mu.Unlock()
}

func (c *ccCoordinator) onRelease(f func()) {
	c.mu.Lock()
	c.releases = append(c.releases, f)
	c.mu.Unlock()
}

// spawn runs fn in a tracked goroutine; a panic is recovered in that goroutine
// and recorded.
func (c *ccCoordinator) spawn(fn func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			if p := recover(); p != nil {
				c.mu.Lock()
				c.panics = append(c.panics, fmt.Sprint(p))
				c.mu.Unlock()
			}
		}()
		fn()
	}()
}

// await waits for ch until the scenario deadline. The coordinator must
// observe the completion before the deadline: a deadline already passed on
// entry, or passed when the completion is observed (a select may pick a ready
// channel over an expired timer), fires the watchdog. Once the watchdog fired,
// every later await fails immediately: the decision is never rewritten.
func (c *ccCoordinator) await(ch <-chan struct{}) bool {
	c.mu.Lock()
	fired, deadline := c.fired, c.deadline
	c.mu.Unlock()
	if fired {
		return false
	}
	if !c.now().Before(deadline) {
		c.fire()
		return false
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-ch:
		if !c.now().Before(deadline) {
			c.fire()
			return false
		}
		return true
	case <-t.C:
		c.fire()
		return false
	}
}

func (c *ccCoordinator) fire() {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	c.mu.Lock()
	c.fired = true
	c.stack = string(buf[:n])
	c.mu.Unlock()
	if c.cfg.onWatchdog != nil {
		c.cfg.onWatchdog()
	}
}

// closeMaterial calls Material.Close in a tracked goroutine and waits for it
// under the watchdog. The outcome itself is in the trace.
func (c *ccCoordinator) closeMaterial(m *Material) bool {
	if c.cfg.closeWatchdog > 0 {
		// Test seam: restart the deadline when Close starts, so a test can
		// drive the watchdog after the fault point is reached.
		c.mu.Lock()
		c.deadline = c.now().Add(c.cfg.closeWatchdog)
		c.mu.Unlock()
	}
	done := make(chan struct{})
	c.spawn(func() {
		defer close(done)
		_ = m.Close()
	})
	return c.await(done)
}

// observe ends the scenario: cancel, release gates, bounded wait for every
// tracked goroutine, then snapshot the trace.
func (c *ccCoordinator) observe(obs ccObservation, tr *ccTrace) ccObservation {
	c.cancel()
	c.mu.Lock()
	releases := append([]func(){}, c.releases...)
	c.mu.Unlock()
	for _, f := range releases {
		f()
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(c.cfg.Quiesce)
	defer t.Stop()
	select {
	case <-done:
		obs.Quiescent = true
	case <-t.C:
		obs.Quiescent = false
	}
	obs.leftover = done

	c.mu.Lock()
	obs.Pairs = append([]ccPairResult(nil), c.pairs...)
	obs.Panics = append([]string(nil), c.panics...)
	obs.WatchdogFired = c.fired
	obs.Stack = c.stack
	c.mu.Unlock()
	sort.Slice(obs.Pairs, func(i, j int) bool { return obs.Pairs[i].ID < obs.Pairs[j].ID })
	obs.Events = tr.snapshot()
	return obs
}

func ccVersionFor(i int) uint16 {
	if i%2 == 0 {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

// runCCC1 is the consumer drain: every pair completes before Close1, then a
// probe pair (POST) and Close2.
func runCCC1(cfg ccConfig, fx *ccFixture, signer crypto.Signer) ccObservation {
	tr := &ccTrace{}
	o := &observedSigner{inner: signer, trace: tr}
	m := Material{Certificate: tlsCertFromSigner(fx.leaf, o)}
	c := newCCCoordinator(cfg, cfg.Watchdog)

	var pw sync.WaitGroup
	for i := 0; i < cfg.C1Pairs; i++ {
		id, ver := i, ccVersionFor(i)
		pw.Add(1)
		c.spawn(func() {
			defer pw.Done()
			c.addPair(runCCPair(c.ctx, fx, o, id, ver, cfg.PipeDeadline))
		})
	}
	all := make(chan struct{})
	c.spawn(func() {
		pw.Wait()
		close(all)
	})

	if c.await(all) && c.closeMaterial(&m) {
		probe := make(chan struct{})
		c.spawn(func() {
			defer close(probe)
			c.addPair(runCCPair(c.ctx, fx, o, cfg.C1Pairs, tls.VersionTLS13, cfg.PipeDeadline))
		})
		if c.await(probe) {
			c.closeMaterial(&m)
		}
	}
	return c.observe(ccObservation{
		Scenario:     "C1",
		ExpectClose2: true,
		Expect:       &ccExpect{Kind: ccKindC1, DrainedPairs: cfg.C1Pairs, ProbeID: cfg.C1Pairs},
	}, tr)
}

// runCCC2 is the deterministic race: the pair is held at the gate before
// delegating to the signer, Close1 runs and returns, then the gate is
// released. Ordering uses signals, never sleeps.
func runCCC2(cfg ccConfig, fx *ccFixture, signer crypto.Signer, name string, version uint16) ccObservation {
	tr := &ccTrace{}
	o := &observedSigner{inner: signer, trace: tr}
	m := Material{Certificate: tlsCertFromSigner(fx.leaf, o)}
	c := newCCCoordinator(cfg, cfg.Watchdog)

	const gateID = 0
	arrived := make(chan struct{})
	var arriveOnce sync.Once
	release := make(chan struct{})
	var releaseOnce sync.Once
	rel := func() { releaseOnce.Do(func() { close(release) }) }
	c.onRelease(rel)
	o.gate = func(conn int) {
		if conn != gateID {
			return
		}
		tr.record(ccGateArrive, conn, nil)
		arriveOnce.Do(func() { close(arrived) })
		<-release
		tr.record(ccGateRelease, conn, nil)
	}

	pairDone := make(chan struct{})
	c.spawn(func() {
		defer close(pairDone)
		c.addPair(runCCPair(c.ctx, fx, o, gateID, version, cfg.PipeDeadline))
	})

	// Wait for the gate or for the pair to end without reaching it (a
	// pre-Sign failure): the latter is not a hang, so the handle is still
	// closed and the verdict reports the missing gate order and pair evidence
	// instead of a watchdog expiry.
	first := make(chan struct{})
	c.spawn(func() {
		defer close(first)
		select {
		case <-arrived:
		case <-pairDone:
		case <-c.ctx.Done():
		}
	})
	if c.await(first) {
		select {
		case <-arrived:
			if c.closeMaterial(&m) {
				rel()
				if c.await(pairDone) {
					c.closeMaterial(&m)
				}
			}
		default:
			if c.closeMaterial(&m) {
				c.closeMaterial(&m)
			}
		}
	}
	return c.observe(ccObservation{
		Scenario:     name,
		ExpectClose2: true,
		Gate:         &ccGateExpectation{Conn: gateID},
		Expect:       &ccExpect{Kind: ccKindC2, GateConn: gateID},
	}, tr)
}

// runCCC3Round is one stress round: workers loop handshakes; Close1 runs after
// the threshold of verified pairs (or at the first failed pair); each worker
// stops after its first pair started once Close1 had returned; then Close2.
func runCCC3Round(cfg ccConfig, fx *ccFixture, signer crypto.Signer, round int) ccObservation {
	tr := &ccTrace{}
	o := &observedSigner{inner: signer, trace: tr}
	m := Material{Certificate: tlsCertFromSigner(fx.leaf, o)}
	c := newCCCoordinator(cfg, cfg.RoundWatchdog)

	trigger := make(chan struct{})
	var triggerOnce sync.Once
	fireTrigger := func() { triggerOnce.Do(func() { close(trigger) }) }
	var verified atomic.Int32
	var closeReturned atomic.Bool
	var nextID atomic.Int64

	var ww sync.WaitGroup
	for w := 0; w < cfg.C3Workers; w++ {
		ver := ccVersionFor(w)
		ww.Add(1)
		c.spawn(func() {
			defer ww.Done()
			for c.ctx.Err() == nil {
				after := closeReturned.Load()
				id := int(nextID.Add(1) - 1)
				r := runCCPair(c.ctx, fx, o, id, ver, cfg.PipeDeadline)
				c.addPair(r)
				if after {
					return
				}
				if r.verified() {
					if int(verified.Add(1)) >= cfg.C3Threshold {
						fireTrigger()
					}
				} else {
					fireTrigger()
				}
			}
		})
	}
	workersDone := make(chan struct{})
	c.spawn(func() {
		ww.Wait()
		close(workersDone)
	})

	if c.await(trigger) && c.closeMaterial(&m) {
		closeReturned.Store(true)
		if c.await(workersDone) {
			c.closeMaterial(&m)
		}
	}
	return c.observe(ccObservation{
		Scenario:     fmt.Sprintf("C3/%02d", round),
		ExpectClose2: true,
		Expect:       &ccExpect{Kind: ccKindC3, MinVerified: cfg.C3Threshold, PostPairs: cfg.C3Workers},
	}, tr)
}

// ---- run of all scenarios on one key ----

type ccHandleRecord struct {
	Label    string
	Closed   bool // the first Close returned
	CloseErr error
}

type ccScenarioReport struct {
	Obs     ccObservation
	Verdict ccVerdict
}

type ccRunOutcome struct {
	Scenarios        []ccScenarioReport
	Handles          []ccHandleRecord
	Notes            []string
	Pass             bool
	ReleaseConfirmed bool

	// OwnershipLost is set when a reopened handle's public key differs from
	// the leaf built on the created key: the key now under the name is not
	// proven to be the one this run created. It vetoes the Delete on its own,
	// independently of ReleaseConfirmed.
	OwnershipLost bool
}

func handleFromObservation(label string, obs ccObservation) ccHandleRecord {
	for _, e := range obs.Events {
		if e.Kind == ccClose1Return {
			return ccHandleRecord{Label: label, Closed: true, CloseErr: e.Err}
		}
	}
	return ccHandleRecord{Label: label}
}

// closeDirect closes a handle that no scenario will use, bounded by Quiesce.
func closeDirect(cfg ccConfig, label string, s crypto.Signer) ccHandleRecord {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("panic: %v", p)
			}
		}()
		done <- closeSigner(s)
	}()
	t := time.NewTimer(cfg.Quiesce)
	defer t.Stop()
	select {
	case err := <-done:
		return ccHandleRecord{Label: label, Closed: true, CloseErr: err}
	case <-t.C:
		return ccHandleRecord{Label: label}
	}
}

// runCCScenarios runs C1 on the created handle, then C2a, C2b and the C3
// rounds, each on a freshly opened handle checked against the leaf. It stops
// at the first scenario that is not PASS. Every acquired handle is recorded
// as pending (Closed=false) immediately after acquisition, and updated with
// the outcome of its first Close.
//
// Limit: the inventory is reported only when runCCScenarios returns. A panic
// on the calling goroutine during preparation (fixture, open, key check) is
// not recovered here and leaves no handle report; the key name persisted
// before Create remains the reference for an authorized recovery.
func runCCScenarios(cfg ccConfig, now time.Time, created crypto.Signer, open func() (crypto.Signer, error)) ccRunOutcome {
	out := ccRunOutcome{}
	register := func(label string) int {
		out.Handles = append(out.Handles, ccHandleRecord{Label: label})
		return len(out.Handles) - 1
	}
	finish := func(pass bool) ccRunOutcome {
		out.Pass = pass
		out.ReleaseConfirmed = true
		for _, s := range out.Scenarios {
			if !s.Verdict.ReleaseConfirmed {
				out.ReleaseConfirmed = false
			}
		}
		for _, h := range out.Handles {
			if !h.Closed || h.CloseErr != nil {
				out.ReleaseConfirmed = false
			}
		}
		return out
	}

	createdIdx := register("create/C1")
	fx, err := newCCFixture(now, created)
	if err != nil {
		out.Notes = append(out.Notes, fmt.Sprintf("fixture: %v", err))
		out.Handles[createdIdx] = closeDirect(cfg, "create/C1", created)
		return finish(false)
	}

	scenario := func(idx int, label string, run func() ccObservation) bool {
		obs := run()
		v := verifyCC(obs)
		out.Scenarios = append(out.Scenarios, ccScenarioReport{Obs: obs, Verdict: v})
		out.Handles[idx] = handleFromObservation(label, obs)
		return v.Outcome == ccPass
	}
	acquire := func(label string) (crypto.Signer, int, bool) {
		s, err := open()
		if err != nil {
			out.Notes = append(out.Notes, fmt.Sprintf("%s: open: %v", label, err))
			return nil, -1, false
		}
		idx := register(label)
		if err := verifyPublicKeyMatch(fx.leaf, s.Public()); err != nil {
			out.Notes = append(out.Notes, fmt.Sprintf("%s: public key check: %v (ownership of the key under this name lost)", label, err))
			out.OwnershipLost = true
			out.Handles[idx] = closeDirect(cfg, label, s)
			return nil, idx, false
		}
		return s, idx, true
	}

	if !scenario(createdIdx, "create/C1", func() ccObservation { return runCCC1(cfg, fx, created) }) {
		return finish(false)
	}
	for _, c2 := range []struct {
		name    string
		version uint16
	}{{"C2a", tls.VersionTLS13}, {"C2b", tls.VersionTLS12}} {
		s, idx, ok := acquire(c2.name)
		if !ok {
			return finish(false)
		}
		if !scenario(idx, c2.name, func() ccObservation { return runCCC2(cfg, fx, s, c2.name, c2.version) }) {
			return finish(false)
		}
	}
	for r := 1; r <= cfg.C3Rounds; r++ {
		label := fmt.Sprintf("C3/%02d", r)
		s, idx, ok := acquire(label)
		if !ok {
			return finish(false)
		}
		if !scenario(idx, label, func() ccObservation { return runCCC3Round(cfg, fx, s, r) }) {
			return finish(false)
		}
	}
	return finish(true)
}

// ---- live orchestration: key ownership and cleanup decisions ----

// ccKeyOps are the key operations of the live run; offline tests use fakes.
type ccKeyOps struct {
	newName   func() (string, error)
	writeDiag func(name string) error
	open      func(name string) (crypto.Signer, error)
	create    func(name string) (crypto.Signer, error)
	del       func(name string) error
}

type ccRunner func(created crypto.Signer, open func() (crypto.Signer, error)) ccRunOutcome

type ccLiveReport struct {
	KeyName         string
	Stage           string // "complete" or where the run stopped
	Run             *ccRunOutcome
	CreateAttempted bool
	DeleteAttempted bool
	DeleteConfirmed bool
	KeyMayRemain    bool
	Pass            bool
}

// executeServingClose owns the single test key: name persisted before Create,
// open-only preflight, Create, scenarios, and at most one exact Delete, only
// when every handle's first Close returned nil and every scenario confirmed
// release. No path retries a Delete or deletes after an unconfirmed release.
func executeServingClose(ops ccKeyOps, run ccRunner, logf func(string, ...any)) ccLiveReport {
	var rep ccLiveReport
	name, err := ops.newName()
	if err != nil {
		rep.Stage = fmt.Sprintf("name: %v", err)
		return rep
	}
	rep.KeyName = name
	if err := ops.writeDiag(name); err != nil {
		rep.Stage = fmt.Sprintf("diagnostics: %v (nothing created)", err)
		return rep
	}
	logf("serving-close key name (persisted before create): %s", name)

	if s, err := ops.open(name); err == nil {
		cerr := closeSigner(s)
		rep.Stage = fmt.Sprintf("preflight: key %q opens (not owned by this run; not reused, not deleted); close of the preflight handle: %v", name, cerr)
		return rep
	} else if !errors.Is(err, ErrKeyNotFound) {
		rep.Stage = fmt.Sprintf("preflight: open %q: %v", name, err)
		return rep
	}

	rep.CreateAttempted = true
	created, err := ops.create(name)
	if err != nil || created == nil {
		rep.KeyMayRemain = true
		rep.Stage = fmt.Sprintf("create %q failed, the key may persist; no delete: %v", name, err)
		return rep
	}

	out := run(created, func() (crypto.Signer, error) { return ops.open(name) })
	rep.Run = &out
	if !out.ReleaseConfirmed {
		rep.KeyMayRemain = true
		rep.Stage = fmt.Sprintf("release not confirmed; key %q kept for an authorized recovery", name)
		return rep
	}
	if out.OwnershipLost {
		// Same evidence as a preflight that opens a key: not proven ours,
		// so it is not deleted (handles are released; inspection first).
		rep.KeyMayRemain = true
		rep.Stage = fmt.Sprintf("a reopened handle of %q has a different public key; key not deleted, kept for inspection and an authorized recovery", name)
		return rep
	}

	rep.DeleteAttempted = true
	if err := ops.del(name); err != nil {
		rep.KeyMayRemain = true
		rep.Stage = fmt.Sprintf("delete %q not confirmed (single attempt, no retry): %v", name, err)
		return rep
	}
	rep.DeleteConfirmed = true
	rep.Pass = out.Pass
	rep.Stage = "complete"
	return rep
}

// newServingCloseKeyName returns a fresh exact test key name.
func newServingCloseKeyName() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate serving-close key suffix: %w", err)
	}
	return identity.TestKeyNamespace + "ServingClose." + hex.EncodeToString(buf[:]), nil
}

// writeServingCloseDiag writes the key name to a new file in dir, syncs and closes
// it, then reads it back. Any error stops the run before Create.
func writeServingCloseDiag(dir, name string) error {
	path := filepath.Join(dir, fmt.Sprintf("serving-close-%d.txt", time.Now().UnixNano()))
	want := "key=" + name + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(want); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(got) != want {
		return fmt.Errorf("diagnostics read-back mismatch in %s", path)
	}
	return nil
}
