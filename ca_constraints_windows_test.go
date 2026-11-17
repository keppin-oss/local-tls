//go:build windows

package localtls

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// TestProvisionMachineRejectsUnconstrainedCA drives the full production
// sequence (pre-check, machine-state check, ProvisionWithKeyStore) on a
// complete existing state whose CA lacks the name constraints and EKU, with
// fake keys, key opener and trust store (no CNG, no real store). The
// pre-checks pass because both DERs and both keys are present and coherent;
// the CA is then rejected by the common validator. The key store is asked once
// for each existing key (reloadExisting opens both before validateCA) and
// creates none; both signers are released. No trust is installed and no file
// changes.
func TestProvisionMachineRejectsUnconstrainedCA(t *testing.T) {
	root := t.TempDir()
	tlsDir := filepath.Join(root, tlsSubDir)
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		t.Fatal(err)
	}
	caSigner, serverSigner := newFakeCloseSigner(), newFakeCloseSigner()
	legacy := caVariant(t, caSigner, nil)
	leaf, err := generateServerCertWithSigner(caTestNow, legacy, caSigner, serverSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(tlsDir, caCertFile), legacy.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(tlsDir, serverCertFile), leaf.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := dirSnapshot(t, root)

	inner := newFakeMachineKeyStore(true, true)
	inner.caSigner, inner.serverSigner = caSigner, serverSigner
	keys := &countingKeyStore{inner: inner}
	opener := &orderedOpener{results: map[string]string{caKeyName: keyOpens, serverKeyName: keyOpens}}
	isPriv, _ := privileged(true, nil)
	installs := 0

	m, err := provisionMachine(root, keys, countingTrustStore(&installs), opener.open, isPriv, fixedNow(caTestNow))
	if !errors.Is(err, ErrCANotConstrained) {
		t.Fatalf("err = %v, want ErrCANotConstrained", err)
	}
	if errors.Is(err, ErrInconsistentMachineState) {
		t.Fatalf("a pre-check rejected the state instead of the common validator: %v", err)
	}
	if m.Certificate.PrivateKey != nil || m.CACertificate != nil {
		t.Fatal("a rejection must return a zero Material")
	}
	opener.assertReleased(t)
	if keys.caCalls != 1 || keys.srCalls != 1 {
		t.Fatalf("key store loads = %d CA / %d server, want 1 / 1", keys.caCalls, keys.srCalls)
	}
	if !caSigner.closed || !serverSigner.closed {
		t.Fatalf("signers released: CA %v, server %v; want both", caSigner.closed, serverSigner.closed)
	}
	if installs != 0 {
		t.Fatalf("trust installs = %d, want 0", installs)
	}
	if after := dirSnapshot(t, root); !maps.Equal(before, after) {
		t.Fatalf("rejection changed the state directory: before %v, after %v", before, after)
	}
}
