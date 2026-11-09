package localtls

import (
	"errors"
	"reflect"
	"testing"
)

// These tests model the key role split with the machineEnv seam: the CA opener
// behaves as windowscng.OpenWithPolicy(PolicyPrivilegedOnly) does for a
// non-privileged caller (ErrPrivilegeRequired before any open) or for a CA key
// still carrying the legacy service-signer DACL (ErrKeyPolicyMismatch). No
// machine key, file outside t.TempDir() or trust store is touched.

// TestAgentRolePathsNeverOpenCAKey proves that the paths available to the
// non-elevated Agent (serving, candidate load, confirm, abandon) succeed
// without ever calling the CA key opener.
func TestAgentRolePathsNeverOpenCAKey(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage() // renewal authority, privileged: CA opener allowed
	caOpens := len(h.caOpen.opened)

	h.caOpen.err = ErrPrivilegeRequired // from here on: non-privileged Agent

	m, err := loadServing(h.env())
	if err != nil {
		t.Fatalf("LoadServingMaterial path: %v", err)
	}
	m.Close()
	cand, err := loadServingCandidate(h.env(), ref)
	if err != nil {
		t.Fatalf("LoadServingCandidate path: %v", err)
	}
	cand.Close()
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("ConfirmServingCandidate path: %v", err)
	}
	if got := len(h.caOpen.opened); got != caOpens {
		t.Fatalf("Agent-role paths opened the CA key %d time(s)", got-caOpens)
	}
	h.assertSignersReleased()
}

// TestAgentRoleAbandonNeedsNoKey proves AbandonServingCandidate opens no key.
func TestAgentRoleAbandonNeedsNoKey(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	ref := h.stage()
	caOpens, srvOpens := len(h.caOpen.opened), len(h.srvOpen.opened)
	h.caOpen.err, h.srvOpen.err = ErrPrivilegeRequired, ErrPrivilegeRequired
	if err := abandonServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	if len(h.caOpen.opened) != caOpens || len(h.srvOpen.opened) != srvOpens {
		t.Fatal("abandon opened a key")
	}
}

// TestCARolePathsFailClosed proves that the paths that need the CA key
// (ReloadMachine and StageServerRenewal) fail closed with the CA policy error,
// release the server handle and write nothing.
func TestCARolePathsFailClosed(t *testing.T) {
	for _, caErr := range []error{ErrPrivilegeRequired, ErrKeyPolicyMismatch} {
		t.Run(caErr.Error(), func(t *testing.T) {
			h := newRenewalHarness(t, harnessIssued)
			h.caOpen.err = caErr
			before := dirSnapshot(t, h.dir)

			if _, err := reloadExisting(h.env(), reportRenewalDue); !errors.Is(err, caErr) {
				t.Fatalf("ReloadMachine path: %v, want %v", err, caErr)
			}
			h.now = h.due()
			if _, err := stageServerRenewal(h.env()); !errors.Is(err, caErr) {
				t.Fatalf("StageServerRenewal path: %v, want %v", err, caErr)
			}
			if after := dirSnapshot(t, h.dir); !reflect.DeepEqual(after, before) {
				t.Fatal("state directory changed")
			}
			h.assertSignersReleased()
		})
	}
}

// TestLegacyServingCompatibleBeforeMigration proves that serving keeps working
// on an installation whose CA key has not been migrated yet: the serving path
// does not depend on the CA key policy at all.
func TestLegacyServingCompatibleBeforeMigration(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.caOpen.err = ErrKeyPolicyMismatch
	m, err := loadServing(h.env())
	if err != nil {
		t.Fatalf("serving before migration: %v", err)
	}
	m.Close()
	if len(h.caOpen.opened) != 0 {
		t.Fatal("serving opened the CA key")
	}
}
