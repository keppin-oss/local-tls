//go:build !windows

package localtls

import "testing"

func TestRenewalAPIUnsupportedOffWindows(t *testing.T) {
	if _, err := StageServerRenewal(); err == nil {
		t.Fatal("StageServerRenewal must fail off Windows")
	}
	ref := CandidateRef{Outcome: RenewalCandidateStaged}
	if _, err := LoadServingCandidate(ref); err == nil {
		t.Fatal("LoadServingCandidate must fail off Windows")
	}
	if err := ConfirmServingCandidate(ref); err == nil {
		t.Fatal("ConfirmServingCandidate must fail off Windows")
	}
	if err := AbandonServingCandidate(ref); err == nil {
		t.Fatal("AbandonServingCandidate must fail off Windows")
	}
	if err := MigrateMachineKeyPolicies(); err == nil {
		t.Fatal("MigrateMachineKeyPolicies must fail off Windows")
	}
}
