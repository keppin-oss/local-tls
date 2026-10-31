package localtls

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Certificate validity is inclusive at the encoded NotBefore and NotAfter
// instants for both the CA and the server certificate, as in RFC 5280 and Go
// crypto/x509: now equal to a bound is valid, one nanosecond outside it is
// not. Separately, a leaf may end exactly when its CA ends but never later
// (ErrLeafOutlivesCA), and a newly staged leaf that would outlive the CA is
// rejected rather than shortened. Every boundary below is taken from a parsed
// DER certificate; X.509 times are encoded in whole seconds.

var serverAuthEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

// boundaryLeaf issues a server certificate for the harness server key with
// the given validity and checks that the encoded bounds are whole seconds.
func boundaryLeaf(h *renewalHarness, notBefore, notAfter time.Time) *x509.Certificate {
	h.t.Helper()
	leaf := issueLeaf(h.t, h.caCert, h.caKey, &h.srvOpen.key.PublicKey, notBefore, notAfter, serverAuthEKU)
	if leaf.NotBefore.Nanosecond() != 0 || leaf.NotAfter.Nanosecond() != 0 {
		h.t.Fatalf("encoded leaf bounds are not whole seconds: %v / %v", leaf.NotBefore, leaf.NotAfter)
	}
	return leaf
}

// innerLeaf has its own NotBefore and NotAfter strictly inside the CA
// validity, so its boundaries are not masked by the CA's.
func innerLeaf(h *renewalHarness) *x509.Certificate {
	start := harnessIssued.Add(time.Hour)
	return boundaryLeaf(h, start, start.Add(serverValidity))
}

// caEndLeaf ends exactly at the CA's encoded NotAfter.
func caEndLeaf(h *renewalHarness) *x509.Certificate {
	return boundaryLeaf(h, h.caCert.NotAfter.Add(-serverValidity), h.caCert.NotAfter)
}

type boundaryPoint struct {
	name  string
	at    time.Time
	valid bool
}

// boundaryPoints returns the four instants around a validity window: -1ns and
// exact at NotBefore, exact and +1ns at NotAfter.
func boundaryPoints(c *x509.Certificate) []boundaryPoint {
	return []boundaryPoint{
		{"NotBefore-1ns", c.NotBefore.Add(-time.Nanosecond), false},
		{"NotBefore", c.NotBefore, true},
		{"NotAfter", c.NotAfter, true},
		{"NotAfter+1ns", c.NotAfter.Add(time.Nanosecond), false},
	}
}

func TestValidityBoundariesInclusive(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	pub := &h.srvOpen.key.PublicKey
	if h.caCert.NotBefore.Nanosecond() != 0 || h.caCert.NotAfter.Nanosecond() != 0 {
		t.Fatal("encoded CA bounds are not whole seconds")
	}

	for _, p := range boundaryPoints(h.caCert) {
		err := validateCA(h.caCert, p.at)
		if p.valid != (err == nil) || (!p.valid && !errors.Is(err, ErrCertificateNotValidNow)) {
			t.Errorf("CA at %s: err = %v, want valid=%v", p.name, err, p.valid)
		}
	}

	leaf := innerLeaf(h)
	for _, p := range boundaryPoints(leaf) {
		err := validateServerLeaf(leaf, h.caCert, pub, p.at)
		if p.valid != (err == nil) || (!p.valid && !errors.Is(err, ErrCertificateNotValidNow)) {
			t.Errorf("leaf at %s: err = %v, want valid=%v", p.name, err, p.valid)
		}
	}

	// A leaf ending exactly at the CA's NotAfter is valid up to and including
	// that shared instant; one nanosecond later both are expired, which is a
	// validity failure, not ErrLeafOutlivesCA.
	equal := caEndLeaf(h)
	if !equal.NotAfter.Equal(h.caCert.NotAfter) {
		t.Fatal("fixture leaf does not end at the CA NotAfter")
	}
	if err := validateServerLeaf(equal, h.caCert, pub, h.caCert.NotAfter); err != nil {
		t.Errorf("leaf ending with the CA, at the shared NotAfter: %v", err)
	}
	err := validateServerLeaf(equal, h.caCert, pub, h.caCert.NotAfter.Add(time.Nanosecond))
	if !errors.Is(err, ErrCertificateNotValidNow) || errors.Is(err, ErrLeafOutlivesCA) {
		t.Errorf("leaf ending with the CA, 1ns after: err = %v, want ErrCertificateNotValidNow only", err)
	}

	// The smallest encodable excess (one second) is rejected.
	longer := boundaryLeaf(h, equal.NotBefore, h.caCert.NotAfter.Add(time.Second))
	if err := validateServerLeaf(longer, h.caCert, pub, equal.NotBefore); !errors.Is(err, ErrLeafOutlivesCA) {
		t.Errorf("leaf ending 1s after the CA: err = %v, want ErrLeafOutlivesCA", err)
	}
}

// assertServingResult checks a loadServing-style result: success transfers
// exactly the server signer to the caller, failure returns zero Material and
// releases every signer. Nothing may be written either way.
func assertServingResult(h *renewalHarness, m Material, err error, valid bool, leafDER []byte) {
	h.t.Helper()
	if valid {
		if err != nil {
			h.t.Fatalf("err = %v, want success", err)
		}
		if !bytes.Equal(m.ServerCertificate.Raw, leafDER) || h.srvOpen.unclosed() != 1 {
			h.t.Fatal("success must return the persisted leaf with only its server signer open")
		}
		m.Close()
	} else {
		if !errors.Is(err, ErrCertificateNotValidNow) {
			h.t.Fatalf("err = %v, want ErrCertificateNotValidNow", err)
		}
		if m.Certificate.PrivateKey != nil || m.ServerCertificate != nil {
			h.t.Fatal("a failure must return a zero Material")
		}
	}
	h.assertSignersReleased()
	if h.tempMade != 0 || h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), leafDER) {
		h.t.Fatal("serving must never write")
	}
}

func TestServingValidityBoundaries(t *testing.T) {
	for _, fixture := range []struct {
		name string
		leaf func(*renewalHarness) *x509.Certificate
		at   func(*renewalHarness, *x509.Certificate) []boundaryPoint
	}{
		{"inner leaf", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) []boundaryPoint { return boundaryPoints(l) }},
		{"leaf ending with CA", caEndLeaf, func(h *renewalHarness, _ *x509.Certificate) []boundaryPoint { return boundaryPoints(h.caCert)[2:] }},
	} {
		probe := newRenewalHarness(t, harnessIssued)
		for _, p := range fixture.at(probe, fixture.leaf(probe)) {
			t.Run(fixture.name+"/"+p.name, func(t *testing.T) {
				h := newRenewalHarness(t, harnessIssued)
				leaf := fixture.leaf(h)
				h.write(serverCertFile, leaf.Raw)
				// Re-derive the instant from this harness's own parsed DER.
				h.now = pointNamed(fixture.at(h, leaf), p.name).at
				m, err := loadServing(h.env())
				assertServingResult(h, m, err, p.valid, leaf.Raw)
				if len(h.caOpen.opened) != 0 {
					t.Fatal("serving must never open the CA key")
				}
			})
		}
	}
}

func pointNamed(points []boundaryPoint, name string) boundaryPoint {
	for _, p := range points {
		if p.name == name {
			return p
		}
	}
	panic("no boundary point " + name)
}

// TestReloadValidityBoundaries covers ReloadMachine's policy: a leaf at its
// exact NotAfter is still valid but due (ErrRenewalDue only); one nanosecond
// later it is expired (ErrRenewalDue and ErrCertificateNotValidNow). A CA
// failure is reported before any renewal decision.
func TestReloadValidityBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		leaf    func(*renewalHarness) *x509.Certificate
		at      func(*renewalHarness, *x509.Certificate) time.Time
		wantIs  []error
		wantNot []error
	}{
		{"leaf NotBefore-1ns", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotBefore.Add(-time.Nanosecond) },
			[]error{ErrCertificateNotValidNow}, []error{ErrRenewalDue}},
		{"leaf NotBefore", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotBefore }, nil, nil},
		{"leaf NotAfter", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotAfter },
			[]error{ErrRenewalDue}, []error{ErrCertificateNotValidNow}},
		{"leaf NotAfter+1ns", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotAfter.Add(time.Nanosecond) },
			[]error{ErrRenewalDue, ErrCertificateNotValidNow}, nil},
		{"CA NotAfter", caEndLeaf, func(h *renewalHarness, _ *x509.Certificate) time.Time { return h.caCert.NotAfter },
			[]error{ErrRenewalDue}, []error{ErrCertificateNotValidNow}},
		{"CA NotAfter+1ns", caEndLeaf, func(h *renewalHarness, _ *x509.Certificate) time.Time { return h.caCert.NotAfter.Add(time.Nanosecond) },
			[]error{ErrCertificateNotValidNow}, []error{ErrRenewalDue}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			leaf := tc.leaf(h)
			h.write(serverCertFile, leaf.Raw)
			h.now = tc.at(h, leaf)
			m, err := reloadExisting(h.env(), reportRenewalDue)
			if tc.wantIs == nil {
				if err != nil {
					t.Fatalf("err = %v, want success", err)
				}
				m.Close()
			}
			for _, want := range tc.wantIs {
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want it to match %v", err, want)
				}
			}
			for _, not := range tc.wantNot {
				if errors.Is(err, not) {
					t.Fatalf("err = %v, must not match %v", err, not)
				}
			}
			if err != nil && (m.Certificate.PrivateKey != nil || m.ServerCertificate != nil) {
				t.Fatal("a failure must return a zero Material")
			}
			h.assertSignersReleased()
			if h.tempMade != 0 || h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), leaf.Raw) {
				t.Fatal("reload must never write")
			}
		})
	}
}

// fixedKeyStore is a MachineKeyStore over existing in-memory keys. It counts
// acquisitions; it never creates a different key.
type fixedKeyStore struct {
	ca, srv          crypto.Signer
	caCalls, srCalls int
}

func (f *fixedKeyStore) LoadOrCreateCAKey() (crypto.Signer, error) {
	f.caCalls++
	return f.ca, nil
}

func (f *fixedKeyStore) LoadOrCreateServerKey() (crypto.Signer, error) {
	f.srCalls++
	return f.srv, nil
}

// provisionDataDir copies the harness CA and server DERs into a fresh
// ProvisionWithKeyStore data directory and returns it.
func provisionDataDir(h *renewalHarness) string {
	h.t.Helper()
	dataDir := filepath.Join(h.t.TempDir(), "data")
	tlsDir := filepath.Join(dataDir, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		h.t.Fatal(err)
	}
	for _, name := range []string{caCertFile, serverCertFile} {
		if err := os.WriteFile(filepath.Join(tlsDir, name), h.read(name), 0600); err != nil {
			h.t.Fatal(err)
		}
	}
	return dataDir
}

// TestExistingStateProvisioningValidityBoundaries covers ProvisionWithKeyStore
// on existing state: a leaf at its exact NotAfter (or ending with the CA, at
// the CA's NotAfter) is verified with a nil error; one nanosecond later it
// fails. Nothing is written and trust is never installed.
func TestExistingStateProvisioningValidityBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		leaf   func(*renewalHarness) *x509.Certificate
		at     func(*renewalHarness, *x509.Certificate) time.Time
		wantIs []error
	}{
		{"leaf NotBefore-1ns", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotBefore.Add(-time.Nanosecond) },
			[]error{ErrCertificateNotValidNow}},
		{"leaf NotBefore", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotBefore }, nil},
		{"leaf NotAfter", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotAfter }, nil},
		{"leaf NotAfter+1ns", innerLeaf, func(_ *renewalHarness, l *x509.Certificate) time.Time { return l.NotAfter.Add(time.Nanosecond) },
			[]error{ErrRenewalDue, ErrCertificateNotValidNow}},
		{"CA NotAfter", caEndLeaf, func(h *renewalHarness, _ *x509.Certificate) time.Time { return h.caCert.NotAfter }, nil},
		{"CA NotAfter+1ns", caEndLeaf, func(h *renewalHarness, _ *x509.Certificate) time.Time { return h.caCert.NotAfter.Add(time.Nanosecond) },
			[]error{ErrCertificateNotValidNow}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			leaf := tc.leaf(h)
			h.write(serverCertFile, leaf.Raw)
			dataDir := provisionDataDir(h)
			before := dirSnapshot(t, dataDir)
			keys := &fixedKeyStore{ca: h.caKey, srv: h.srvOpen.key}
			installs := 0

			m, err := ProvisionWithKeyStore(dataDir, keys, countingTrustStore(&installs), fixedNow(tc.at(h, leaf)))
			if tc.wantIs == nil {
				if err != nil {
					t.Fatalf("err = %v, want verified existing state", err)
				}
				if !bytes.Equal(m.ServerCertificate.Raw, leaf.Raw) {
					t.Fatal("existing-state provisioning must return the persisted leaf")
				}
			}
			for _, want := range tc.wantIs {
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want it to match %v", err, want)
				}
			}
			if installs != 0 || keys.caCalls != 1 || keys.srCalls != 1 {
				t.Fatalf("installs=%d key acquisitions=%d/%d, want 0 and 1/1", installs, keys.caCalls, keys.srCalls)
			}
			if after := dirSnapshot(t, dataDir); !maps.Equal(before, after) {
				t.Fatal("existing-state provisioning must not write")
			}
		})
	}
}

// TestStageValidityBoundaries covers StageServerRenewal at the CA boundary. A
// renewal that ends exactly at the CA's NotAfter is staged with that exact
// NotAfter; starting one nanosecond later it would outlive the CA and is
// rejected with ErrLeafOutlivesCA (never capped). At the CA's exact NotAfter
// the CA is still valid but no leaf fits; one nanosecond later the CA itself
// is expired. A rejection never writes or overwrites the pending candidate or
// the persisted certificate.
func TestStageValidityBoundaries(t *testing.T) {
	stalePending := []byte("stale pending candidate")
	cases := []struct {
		name    string
		at      func(ca *x509.Certificate) time.Time
		staged  bool
		wantIs  error
		wantNot error
	}{
		{"renewal ends at CA NotAfter", func(ca *x509.Certificate) time.Time { return ca.NotAfter.Add(-serverValidity) }, true, nil, nil},
		{"renewal ends 1ns after CA NotAfter", func(ca *x509.Certificate) time.Time { return ca.NotAfter.Add(-serverValidity + time.Nanosecond) }, false, ErrLeafOutlivesCA, ErrCertificateNotValidNow},
		{"at CA NotAfter", func(ca *x509.Certificate) time.Time { return ca.NotAfter }, false, ErrLeafOutlivesCA, ErrCertificateNotValidNow},
		{"CA NotAfter+1ns", func(ca *x509.Certificate) time.Time { return ca.NotAfter.Add(time.Nanosecond) }, false, ErrCertificateNotValidNow, ErrLeafOutlivesCA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.write(pendingServerCertFile, stalePending)
			h.now = tc.at(h.caCert)

			ref, err := stageServerRenewal(h.env())
			h.assertSignersReleased()
			h.assertNoTemps()
			if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
				t.Fatal("stage must never change the persisted server certificate")
			}
			if !tc.staged {
				if !errors.Is(err, tc.wantIs) || errors.Is(err, tc.wantNot) {
					t.Fatalf("err = %v, want %v and not %v", err, tc.wantIs, tc.wantNot)
				}
				if !bytes.Equal(h.read(pendingServerCertFile), stalePending) {
					t.Fatal("a rejected stage must leave the pending file untouched")
				}
				return
			}
			if err != nil || ref.Outcome != RenewalCandidateStaged {
				t.Fatalf("stage: ref=%+v err=%v, want a staged candidate", ref, err)
			}
			cand, err := x509.ParseCertificate(h.read(pendingServerCertFile))
			if err != nil {
				t.Fatal(err)
			}
			if !cand.NotAfter.Equal(h.caCert.NotAfter) {
				t.Fatalf("candidate NotAfter = %v, want exactly the CA NotAfter %v", cand.NotAfter, h.caCert.NotAfter)
			}

			// The staged candidate serves up to and including the shared
			// NotAfter, and not one nanosecond later.
			h.now = h.caCert.NotAfter
			m, err := loadServingCandidate(h.env(), ref)
			if err != nil {
				t.Fatalf("candidate at CA NotAfter: %v", err)
			}
			m.Close()
			h.now = h.caCert.NotAfter.Add(time.Nanosecond)
			if _, err := loadServingCandidate(h.env(), ref); !errors.Is(err, ErrCertificateNotValidNow) {
				t.Fatalf("candidate 1ns after CA NotAfter: err = %v, want ErrCertificateNotValidNow", err)
			}
			h.assertSignersReleased()
		})
	}
}

// dirSnapshot returns every file under root with its content.
func dirSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		snap[path] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}
