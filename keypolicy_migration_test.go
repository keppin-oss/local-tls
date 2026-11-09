package localtls

import (
	"crypto"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeCAPolicyKey models the CA key DACL state machine of
// windowscng.ApplyPolicy/OpenWithPolicy(PolicyPrivilegedOnly) without touching a
// machine key. state is "service-signer" (legacy), "privileged-only", or any
// other value for an unrecognized DACL.
type fakeCAPolicyKey struct {
	state    string
	applyErr error // returned by apply before any state change when set
	writes   int
}

func (k *fakeCAPolicyKey) apply() error {
	if k.applyErr != nil {
		return k.applyErr
	}
	switch k.state {
	case "privileged-only":
		return nil
	case "service-signer":
		k.state = "privileged-only"
		k.writes++
		return nil
	default:
		return ErrKeyPolicyMismatch
	}
}

// migrationHarness wires migrateKeyPolicies to fakes and records the order of
// the dependency calls.
type migrationHarness struct {
	*renewalHarness
	privileged bool
	privErr    error
	caKey      *fakeCAPolicyKey
	calls      []string
}

func newMigrationHarness(t *testing.T) *migrationHarness {
	return &migrationHarness{
		renewalHarness: newRenewalHarness(t, harnessIssued),
		privileged:     true,
		caKey:          &fakeCAPolicyKey{state: "service-signer"},
	}
}

func (h *migrationHarness) migration() keyPolicyMigration {
	return keyPolicyMigration{
		tlsDir: h.dir,
		fs:     h.fs,
		isPrivileged: func() (bool, error) {
			h.calls = append(h.calls, "privileged")
			return h.privileged, h.privErr
		},
		openServerKey: func() (crypto.Signer, error) {
			h.calls = append(h.calls, "openServer")
			return h.srvOpen.open()
		},
		tightenCAKey: func() error {
			h.calls = append(h.calls, "tightenCA")
			return h.caKey.apply()
		},
		openCAKey: func() (crypto.Signer, error) {
			h.calls = append(h.calls, "openCA")
			if h.caKey.state != "privileged-only" {
				return nil, ErrKeyPolicyMismatch
			}
			return h.caOpen.open()
		},
	}
}

func (h *migrationHarness) assertCalls(want ...string) {
	h.t.Helper()
	if want == nil {
		want = []string{}
	}
	got := h.calls
	if got == nil {
		got = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		h.t.Fatalf("calls = %v, want %v", got, want)
	}
}

func (h *migrationHarness) assertNoRotation(caDER, srvDER []byte) {
	h.t.Helper()
	if got := h.read(caCertFile); string(got) != string(caDER) {
		h.t.Fatal("CA certificate DER changed")
	}
	if got := h.read(serverCertFile); string(got) != string(srvDER) {
		h.t.Fatal("server certificate DER changed")
	}
	h.assertSignersReleased()
}

func TestMigrateKeyPoliciesTightensLegacyCAKey(t *testing.T) {
	h := newMigrationHarness(t)
	caDER, srvDER := h.read(caCertFile), h.read(serverCertFile)

	if err := migrateKeyPolicies(h.migration()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h.assertCalls("privileged", "openServer", "tightenCA", "openCA")
	if h.caKey.state != "privileged-only" || h.caKey.writes != 1 {
		t.Fatalf("CA key state %q after %d writes, want privileged-only after 1", h.caKey.state, h.caKey.writes)
	}
	h.assertNoRotation(caDER, srvDER)
}

func TestMigrateKeyPoliciesIdempotent(t *testing.T) {
	h := newMigrationHarness(t)
	caDER, srvDER := h.read(caCertFile), h.read(serverCertFile)

	for i := 0; i < 3; i++ {
		if err := migrateKeyPolicies(h.migration()); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	if h.caKey.writes != 1 {
		t.Fatalf("DACL written %d times over three runs, want 1", h.caKey.writes)
	}
	h.assertNoRotation(caDER, srvDER)
}

func TestMigrateKeyPoliciesAlreadyPrivilegedOnly(t *testing.T) {
	h := newMigrationHarness(t)
	h.caKey.state = "privileged-only"
	if err := migrateKeyPolicies(h.migration()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if h.caKey.writes != 0 {
		t.Fatalf("an already privileged-only CA key was rewritten %d times", h.caKey.writes)
	}
}

func TestMigrateKeyPoliciesRequiresPrivilege(t *testing.T) {
	for _, tc := range []struct {
		name    string
		priv    bool
		privErr error
	}{
		{name: "not privileged"},
		{name: "privilege unknown", priv: true, privErr: errors.New("token query failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMigrationHarness(t)
			h.privileged, h.privErr = tc.priv, tc.privErr
			err := migrateKeyPolicies(h.migration())
			if !errors.Is(err, ErrPrivilegeRequired) {
				t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
			}
			h.assertCalls("privileged")
			if h.caKey.state != "service-signer" || h.caKey.writes != 0 {
				t.Fatal("a non-privileged migration modified the CA key")
			}
		})
	}
}

func TestMigrateKeyPoliciesRequiresCompleteState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(h *migrationHarness)
		wantIs  error
		wantMsg string
	}{
		{name: "CA DER missing", mutate: func(h *migrationHarness) { h.remove(caCertFile) }, wantIs: ErrInconsistentMachineState, wantMsg: "CA certificate is missing"},
		{name: "server DER missing", mutate: func(h *migrationHarness) { h.remove(serverCertFile) }, wantIs: ErrInconsistentMachineState, wantMsg: "server certificate is missing"},
		{name: "CA DER corrupt", mutate: func(h *migrationHarness) { h.write(caCertFile, []byte("not a certificate")) }, wantIs: ErrInconsistentMachineState},
		{name: "CA DER unreadable", mutate: func(h *migrationHarness) {
			read := h.fs.readFile
			h.fs.readFile = func(p string) ([]byte, error) {
				if filepath.Base(p) == caCertFile {
					return nil, fs.ErrPermission
				}
				return read(p)
			}
		}, wantIs: fs.ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMigrationHarness(t)
			tc.mutate(h)
			err := migrateKeyPolicies(h.migration())
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("err = %v, want %v", err, tc.wantIs)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err %q does not mention %q", err, tc.wantMsg)
			}
			h.assertCalls("privileged")
			if h.caKey.writes != 0 {
				t.Fatal("CA key modified for incomplete state")
			}
		})
	}
}

func TestMigrateKeyPoliciesServerKeyFailureStopsBeforeCAWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(h *migrationHarness)
		wantIs error
	}{
		{name: "server key not found", mutate: func(h *migrationHarness) { h.srvOpen.err = ErrKeyNotFound }, wantIs: ErrKeyNotFound},
		{name: "server key policy mismatch", mutate: func(h *migrationHarness) { h.srvOpen.err = ErrKeyPolicyMismatch }, wantIs: ErrKeyPolicyMismatch},
		{name: "server key does not match certificate", mutate: func(h *migrationHarness) { h.srvOpen.key = mustKey(h.t) }, wantIs: ErrInconsistentMachineState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMigrationHarness(t)
			tc.mutate(h)
			err := migrateKeyPolicies(h.migration())
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("err = %v, want %v", err, tc.wantIs)
			}
			h.assertCalls("privileged", "openServer")
			if h.caKey.writes != 0 {
				t.Fatal("CA key modified after a server key failure")
			}
			h.assertSignersReleased()
		})
	}
}

func TestMigrateKeyPoliciesCAKeyNotFoundIsNotAbsence(t *testing.T) {
	h := newMigrationHarness(t)
	h.caKey.applyErr = ErrKeyNotFound
	err := migrateKeyPolicies(h.migration())
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
	if !strings.Contains(err.Error(), "does not prove that it is absent") || !strings.Contains(err.Error(), "nothing was created") {
		t.Fatalf("err %q must state that not-found is not proof of absence", err)
	}
	h.assertCalls("privileged", "openServer", "tightenCA")
}

func TestMigrateKeyPoliciesUnexpectedCADACLFailsClosed(t *testing.T) {
	h := newMigrationHarness(t)
	h.caKey.state = "unrecognized"
	err := migrateKeyPolicies(h.migration())
	if !errors.Is(err, ErrKeyPolicyMismatch) {
		t.Fatalf("err = %v, want ErrKeyPolicyMismatch", err)
	}
	h.assertCalls("privileged", "openServer", "tightenCA")
	if h.caKey.state != "unrecognized" || h.caKey.writes != 0 {
		t.Fatal("an unrecognized CA DACL was rewritten")
	}
}

func TestMigrateKeyPoliciesPostWriteFailurePropagates(t *testing.T) {
	h := newMigrationHarness(t)
	verifyErr := errors.New("post-write DACL verification failed")
	h.caKey.applyErr = verifyErr
	if err := migrateKeyPolicies(h.migration()); !errors.Is(err, verifyErr) {
		t.Fatalf("err = %v, want the post-write verification failure", err)
	}
	h.assertCalls("privileged", "openServer", "tightenCA")
}

func TestMigrateKeyPoliciesCAKeyMismatchAfterTighten(t *testing.T) {
	h := newMigrationHarness(t)
	h.caOpen.key = mustKey(t)
	err := migrateKeyPolicies(h.migration())
	if !errors.Is(err, ErrInconsistentMachineState) || !strings.Contains(err.Error(), "CA cert/key mismatch") {
		t.Fatalf("err = %v, want CA cert/key mismatch", err)
	}
	h.assertCalls("privileged", "openServer", "tightenCA", "openCA")
	if h.caKey.state != "privileged-only" {
		t.Fatal("the tightened CA DACL must never be widened back")
	}
	h.assertSignersReleased()
}

func TestMigrateKeyPoliciesDetectsCADERChange(t *testing.T) {
	h := newMigrationHarness(t)
	m := h.migration()
	open := m.openCAKey
	m.openCAKey = func() (crypto.Signer, error) {
		h.write(caCertFile, append(h.read(caCertFile), 0))
		return open()
	}
	err := migrateKeyPolicies(m)
	if !errors.Is(err, ErrInconsistentMachineState) || !strings.Contains(err.Error(), "changed during the key policy migration") {
		t.Fatalf("err = %v, want CA DER change detection", err)
	}
}

func (h *migrationHarness) remove(name string) {
	h.t.Helper()
	if err := os.Remove(filepath.Join(h.dir, name)); err != nil {
		h.t.Fatal(err)
	}
}
