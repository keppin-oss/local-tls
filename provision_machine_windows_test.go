//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keppin-oss/cng/windowscng"
)

// Combined R-1 coverage: provisionMachine runs the private pre-check and the
// public machine-state check in order before ProvisionWithKeyStore. These
// offline tests drive that exact sequence with an open-only fake opener, a
// counting key store and a counting trust store.

const (
	keyOpens    = "opens"
	keyNotFound = "not-found"
)

// orderedOpener is an open-only opener keyed by production key name. A name
// mapped to keyOpens returns a fresh closable handle, keyNotFound returns the
// production ErrKeyNotFound mapping of a windowscng not-found error (key name
// and native HRESULT in the text), and any other entry in errs is returned
// as is. It records the open order, every handle and every error returned.
type orderedOpener struct {
	results  map[string]string
	errs     map[string]error
	order    []string
	handles  []*fakeCloseSigner
	returned map[string]error
}

func (o *orderedOpener) open(name string) (crypto.Signer, error) {
	o.order = append(o.order, name)
	if o.returned == nil {
		o.returned = map[string]error{}
	}
	if err, ok := o.errs[name]; ok {
		o.returned[name] = err
		return nil, err
	}
	switch o.results[name] {
	case keyOpens:
		s := newFakeCloseSigner()
		o.handles = append(o.handles, s)
		return s, nil
	case keyNotFound:
		err := mapCNGError(fmt.Errorf("%w: open key %q: NCryptOpenKey: hr=0x80090016", windowscng.ErrKeyNotFound, name))
		o.returned[name] = err
		return nil, err
	default:
		panic("orderedOpener: no result for " + name)
	}
}

func (o *orderedOpener) assertReleased(t *testing.T) {
	t.Helper()
	for i, h := range o.handles {
		if !h.closed {
			t.Fatalf("probe handle %d was not closed", i)
		}
	}
}

func TestProvisionMachineCombinedGuardsReject(t *testing.T) {
	accessErr := errors.New("NCryptOpenKey: hr=0x80090010")
	privErr := errors.New("token query failed")
	ca, srv := caKeyName, serverKeyName

	cases := []struct {
		name      string
		ders      []string // certificate DERs written before the call
		unknownCA bool     // CA DER stat fails with a permission error
		results   map[string]string
		errs      map[string]error
		privOK    bool
		privErr   error
		wantIs    []error
		wantNot   []error
		wantCause []string // keys whose not-found open error must be in the chain
		wantText  []string
		wantOpens []string
		wantPriv  int
	}{
		{name: "no DER, non-privileged",
			results: map[string]string{ca: keyNotFound, srv: keyNotFound},
			wantIs:  []error{ErrKeyNotFound}, wantNot: []error{ErrInconsistentMachineState},
			wantCause: []string{ca}, wantOpens: []string{ca}, wantPriv: 1},
		{name: "no DER, privilege unknown",
			results: map[string]string{ca: keyNotFound, srv: keyNotFound}, privOK: true, privErr: privErr,
			wantIs: []error{ErrKeyNotFound, privErr}, wantCause: []string{ca}, wantOpens: []string{ca}, wantPriv: 1},
		{name: "no DER, CA key opens",
			results: map[string]string{ca: keyOpens, srv: keyNotFound}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState}, wantNot: []error{ErrKeyNotFound},
			wantText: []string{ca}, wantOpens: []string{ca}},
		{name: "no DER, CA unexpected open error",
			errs: map[string]error{ca: accessErr}, privOK: true,
			wantIs: []error{accessErr}, wantNot: []error{ErrInconsistentMachineState}, wantOpens: []string{ca}},
		{name: "no DER, privileged, server key opens",
			results: map[string]string{ca: keyNotFound, srv: keyOpens}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState}, wantText: []string{srv}, wantOpens: []string{ca, ca, srv}, wantPriv: 1},
		{name: "no DER, privileged, server unexpected open error",
			results: map[string]string{ca: keyNotFound}, errs: map[string]error{srv: accessErr}, privOK: true,
			wantIs: []error{accessErr}, wantNot: []error{ErrInconsistentMachineState}, wantOpens: []string{ca, ca, srv}, wantPriv: 1},
		{name: "server DER only",
			ders: []string{serverCertFile}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState}},
		{name: "CA DER only",
			ders: []string{caCertFile}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState}},
		{name: "CA DER presence unknown",
			unknownCA: true, privOK: true,
			wantIs: []error{ErrInconsistentMachineState}, wantText: []string{"permission"}},
		{name: "both DERs, CA key not found",
			ders: []string{caCertFile, serverCertFile}, results: map[string]string{ca: keyNotFound, srv: keyOpens}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState, ErrKeyNotFound}, wantCause: []string{ca},
			wantText: []string{ca, "0x80090016"}, wantOpens: []string{ca, srv}},
		{name: "both DERs, server key not found",
			ders: []string{caCertFile, serverCertFile}, results: map[string]string{ca: keyOpens, srv: keyNotFound}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState, ErrKeyNotFound}, wantCause: []string{srv},
			wantText: []string{srv, "0x80090016"}, wantOpens: []string{ca, srv}},
		{name: "both DERs, both keys not found",
			ders: []string{caCertFile, serverCertFile}, results: map[string]string{ca: keyNotFound, srv: keyNotFound}, privOK: true,
			wantIs: []error{ErrInconsistentMachineState, ErrKeyNotFound}, wantCause: []string{ca, srv},
			wantText: []string{ca, srv}, wantOpens: []string{ca, srv}},
		{name: "both DERs, CA unexpected open error",
			ders: []string{caCertFile, serverCertFile}, errs: map[string]error{ca: accessErr}, privOK: true,
			wantIs: []error{accessErr}, wantNot: []error{ErrInconsistentMachineState}, wantOpens: []string{ca}},
		{name: "both DERs, server unexpected open error",
			ders: []string{caCertFile, serverCertFile}, results: map[string]string{ca: keyOpens}, errs: map[string]error{srv: accessErr}, privOK: true,
			wantIs: []error{accessErr}, wantNot: []error{ErrInconsistentMachineState}, wantOpens: []string{ca, srv}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tlsDir := filepath.Join(root, tlsSubDir)
			if err := os.MkdirAll(tlsDir, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range tc.ders {
				if err := os.WriteFile(filepath.Join(tlsDir, name), []byte("der"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.unknownCA {
				saved := osFS
				t.Cleanup(func() { osFS = saved })
				caPath := filepath.Join(tlsDir, caCertFile)
				osFS.stat = func(p string) (fs.FileInfo, error) {
					if p == caPath {
						return nil, fs.ErrPermission
					}
					return saved.stat(p)
				}
			}
			before := dirSnapshot(t, root)

			opener := &orderedOpener{results: tc.results, errs: tc.errs}
			isPriv, privCalls := privileged(tc.privOK, tc.privErr)
			keys := &countingKeyStore{inner: newFakeMachineKeyStore(true, true)}
			installs := 0

			m, err := provisionMachine(root, keys, countingTrustStore(&installs), opener.open, isPriv, fixedNow(harnessIssued))
			if err == nil {
				t.Fatal("expected a fail-closed rejection")
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
			for _, name := range tc.wantCause {
				if cause := opener.returned[name]; cause == nil || !errors.Is(err, cause) {
					t.Fatalf("err = %v, want the original open error of %q in the chain", err, name)
				}
			}
			for _, text := range tc.wantText {
				if !strings.Contains(err.Error(), text) {
					t.Fatalf("err = %v, want it to mention %q", err, text)
				}
			}
			if !slices.Equal(opener.order, tc.wantOpens) {
				t.Fatalf("open order = %v, want %v", opener.order, tc.wantOpens)
			}
			if *privCalls != tc.wantPriv {
				t.Fatalf("privilege queries = %d, want %d", *privCalls, tc.wantPriv)
			}
			opener.assertReleased(t)
			if m.Certificate.PrivateKey != nil || m.CACertificate != nil {
				t.Fatal("a rejection must return a zero Material")
			}
			if keys.caCalls+keys.srCalls != 0 || installs != 0 {
				t.Fatalf("rejection acquired/created keys (%d/%d) or installed trust (%d)", keys.caCalls, keys.srCalls, installs)
			}
			if after := dirSnapshot(t, root); !maps.Equal(before, after) {
				t.Fatalf("rejection changed the state directory: before %v, after %v", before, after)
			}
		})
	}
}

// TestProvisionMachineCombinedGuardsHealthy proves the union of both guards
// keeps the healthy flows usable: a privileged first install with both keys
// not found proceeds to ProvisionWithKeyStore, and the following call on the
// complete state probes both keys (closing the handles), verifies the existing
// state and writes nothing.
func TestProvisionMachineCombinedGuardsHealthy(t *testing.T) {
	root := t.TempDir()
	keys := &countingKeyStore{inner: newFakeMachineKeyStore(true, true)}
	isPriv, _ := privileged(true, nil)

	first := &orderedOpener{results: map[string]string{caKeyName: keyNotFound, serverKeyName: keyNotFound}}
	installs := 0
	m1, err := provisionMachine(root, keys, countingTrustStore(&installs), first.open, isPriv, fixedNow(harnessIssued))
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	if !slices.Equal(first.order, []string{caKeyName, caKeyName, serverKeyName}) {
		t.Fatalf("first install open order = %v", first.order)
	}
	if keys.caCalls != 1 || keys.srCalls != 1 || installs != 1 {
		t.Fatalf("first install: key acquisitions %d/%d, installs %d; want 1/1/1", keys.caCalls, keys.srCalls, installs)
	}
	m1.Close()

	before := dirSnapshot(t, root)
	second := &orderedOpener{results: map[string]string{caKeyName: keyOpens, serverKeyName: keyOpens}}
	installs = 0
	m2, err := provisionMachine(root, keys, countingTrustStore(&installs), second.open, isPriv, fixedNow(harnessIssued.Add(time.Hour)))
	if err != nil {
		t.Fatalf("existing complete state: %v", err)
	}
	defer m2.Close()
	if !slices.Equal(second.order, []string{caKeyName, serverKeyName}) {
		t.Fatalf("existing state open order = %v", second.order)
	}
	second.assertReleased(t)
	if installs != 0 || m2.CAFingerprintSHA256 != m1.CAFingerprintSHA256 {
		t.Fatal("existing state must not install trust or change the CA identity")
	}
	if after := dirSnapshot(t, root); !maps.Equal(before, after) {
		t.Fatal("existing state verification must not write")
	}
}
