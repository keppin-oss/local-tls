//go:build windows

package localtls

import (
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadServingMaterialTrustStates proves LoadServingMaterial's validation
// core fails closed unless the CA trust state is TrustHealthy, and that the
// server signer is released on every new error path.
func TestLoadServingMaterialTrustStates(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	caCert, caKey, err := generateCA(now)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	serverCert, serverKey, err := generateServerCert(now, caCert, caKey)
	if err != nil {
		t.Fatalf("generateServerCert: %v", err)
	}

	cases := []struct {
		name       string
		state      TrustState
		trustErr   error
		wantErr    bool
		wantClosed bool
	}{
		{name: "healthy", state: TrustHealthy, wantErr: false, wantClosed: false},
		{name: "absent", state: TrustAbsent, wantErr: true, wantClosed: true},
		{name: "conflict", state: TrustConflict, wantErr: true, wantClosed: true},
		{name: "verify error", state: TrustError, trustErr: errors.New("store unavailable"), wantErr: true, wantClosed: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeTrustStore{
				verify: func([]byte) (TrustState, error) { return tc.state, tc.trustErr },
			}
			signer := &fakeCloseSigner{key: serverKey}

			material, err := loadServingMaterial(caCert, serverCert, signer, store)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for trust state %s, got nil", tc.state)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if material.Certificate.PrivateKey != signer {
					t.Fatalf("Material.Certificate.PrivateKey = %T, want server signer", material.Certificate.PrivateKey)
				}
			}

			if tc.wantClosed && !signer.closed {
				t.Fatalf("server signer was not closed on error path (state %s)", tc.state)
			}
			if !tc.wantClosed && signer.closed {
				t.Fatalf("server signer must not be closed on success (state %s)", tc.state)
			}
		})
	}
}

// TestCheckInconsistentMachineStatePartialDER proves the guard flags partial
// certificate state (one DER present without the other) as inconsistent without
// probing the key store.
func TestCheckInconsistentMachineStatePartialDER(t *testing.T) {
	root := t.TempDir()
	tlsDir := filepath.Join(root, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir tls dir: %v", err)
	}

	open := func(string) (crypto.Signer, error) {
		t.Fatal("key probe must not run for partial DER state")
		return nil, nil
	}

	// CA DER present, server DER absent → inconsistent.
	if err := os.WriteFile(filepath.Join(tlsDir, caCertFile), []byte("ca"), 0600); err != nil {
		t.Fatalf("write CA DER: %v", err)
	}
	inconsistent, err := checkInconsistentMachineState(root, open)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !inconsistent {
		t.Fatal("expected inconsistent state when CA DER present and server DER absent")
	}
}

// TestCheckInconsistentMachineStateCompleteDERMissingKey proves that complete
// certificate DERs with missing keys are inconsistent (fail closed before any
// key creation), and that the pre-check probes keys via the open-only seam.
func TestCheckInconsistentMachineStateCompleteDERMissingKey(t *testing.T) {
	root := t.TempDir()
	tlsDir := filepath.Join(root, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir tls dir: %v", err)
	}
	for name, data := range map[string]string{caCertFile: "ca", serverCertFile: "server"} {
		if err := os.WriteFile(filepath.Join(tlsDir, name), []byte(data), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	opens := 0
	open := func(string) (crypto.Signer, error) {
		opens++
		return nil, ErrKeyNotFound
	}

	inconsistent, err := checkInconsistentMachineState(root, open)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !inconsistent {
		t.Fatal("complete DER with missing keys must be inconsistent (fail closed)")
	}
	if opens != 2 {
		t.Fatalf("expected 2 key probes (open-only), got %d", opens)
	}
}

// TestCheckInconsistentMachineStateUnexpectedOpenError proves that an open
// failure other than ErrKeyNotFound is propagated (fail closed) rather than
// being misclassified as an absent key.
func TestCheckInconsistentMachineStateUnexpectedOpenError(t *testing.T) {
	root := t.TempDir()
	tlsDir := filepath.Join(root, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatalf("mkdir tls dir: %v", err)
	}

	permErr := errors.New("access denied")
	open := func(string) (crypto.Signer, error) {
		return nil, permErr
	}

	_, err := checkInconsistentMachineState(root, open)
	if err == nil {
		t.Fatal("expected open error to propagate")
	}
	if !errors.Is(err, permErr) {
		t.Fatalf("error = %v, want %v", err, permErr)
	}
}

// TestProbeKeyClassifiesOpenErrors proves the key probe distinguishes absent
// (ErrKeyNotFound), unexpected failure, and present-with-close.
func TestProbeKeyClassifiesOpenErrors(t *testing.T) {
	present, err := probeKey(func(string) (crypto.Signer, error) { return nil, ErrKeyNotFound }, "k")
	if present || err != nil {
		t.Fatalf("absent: present=%v err=%v, want present=false err=nil", present, err)
	}

	permErr := errors.New("access denied")
	present, err = probeKey(func(string) (crypto.Signer, error) { return nil, permErr }, "k")
	if present || !errors.Is(err, permErr) {
		t.Fatalf("unexpected: present=%v err=%v, want present=false err=permErr", present, err)
	}

	signer := newFakeCloseSigner()
	present, err = probeKey(func(string) (crypto.Signer, error) { return signer, nil }, "k")
	if !present || err != nil {
		t.Fatalf("present: present=%v err=%v, want present=true err=nil", present, err)
	}
	if !signer.closed {
		t.Fatal("probe must close the opened signer")
	}
}
