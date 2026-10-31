package localtls

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"
)

// TestServingTrustVerifierErrorClosesSigner covers the serving paths when the
// read-only trust verifier itself fails (not an absent or conflicting state).
// Serving opens its server signer before verifying trust, so the error must
// close that signer, keep the verifier's cause in the chain, return a zero
// Material, never open the CA key and never write. The success case proves
// the opposite ownership: the signer is transferred to the caller open.
func TestServingTrustVerifierErrorClosesSigner(t *testing.T) {
	verifierErr := errors.New("CertOpenStore: hr=0x80092004")

	t.Run("serving success transfers the signer", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		m, err := loadServing(h.env())
		if err != nil {
			t.Fatalf("loadServing: %v", err)
		}
		if h.srvOpen.unclosed() != 1 || len(h.caOpen.opened) != 0 {
			t.Fatal("success must leave exactly the server signer open and never open the CA key")
		}
		if err := m.Close(); err != nil || h.srvOpen.unclosed() != 0 {
			t.Fatal("Material.Close must release the transferred server signer")
		}
	})

	t.Run("serving", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		h.trust.err = verifierErr
		m, err := loadServing(h.env())
		assertVerifierFailure(h, m, err, verifierErr)
	})

	t.Run("candidate", func(t *testing.T) {
		h := newRenewalHarness(t, harnessIssued)
		h.now = h.due()
		ref := h.stage()
		pending := h.read(pendingServerCertFile)
		caOpens := len(h.caOpen.opened)
		h.tempMade = 0

		h.trust.err = verifierErr
		m, err := loadServingCandidate(h.env(), ref)
		assertVerifierFailure(h, m, err, verifierErr)
		if len(h.caOpen.opened) != caOpens {
			t.Fatal("candidate load must never open the CA key")
		}
		if !bytes.Equal(h.read(pendingServerCertFile), pending) {
			t.Fatal("candidate load must not change the pending candidate")
		}
	})
}

func assertVerifierFailure(h *renewalHarness, m Material, err, cause error) {
	h.t.Helper()
	if !errors.Is(err, cause) {
		h.t.Fatalf("err = %v, want the verifier error in the chain", err)
	}
	if errors.Is(err, ErrTrustNotHealthy) {
		h.t.Fatalf("a verifier failure is not a trust state: %v", err)
	}
	if m.Certificate.PrivateKey != nil || m.ServerCertificate != nil || m.CACertificate != nil {
		h.t.Fatal("a failure must return a zero Material")
	}
	if len(h.srvOpen.opened) == 0 {
		h.t.Fatal("serving must have opened the server signer before verifying trust")
	}
	h.assertSignersReleased()
	if h.tempMade != 0 || !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
		h.t.Fatal("serving must never write")
	}
}

// wrongSANs are DNS SAN sets that the production identity check must reject.
// Each certificate is actually encoded and signed by the harness CA for the
// harness server key, so only the SAN policy fails.
var wrongSANs = map[string][]string{
	"foreign name":          {"evil.local"},
	"localhost plus extra":  {"localhost", "evil.local"},
	"no DNS SAN (IPs only)": nil,
}

func assertSANRejected(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "SAN") {
		t.Fatalf("err = %v, want a SAN validation failure", err)
	}
}

// TestProductionPathsRejectWrongSAN runs a signed wrong-SAN certificate through
// the production serving, reload, existing-state provisioning, Stage,
// candidate-load and Confirm cores (not the test-only legacy Provision).
// Every rejection releases its signers and writes nothing.
func TestProductionPathsRejectWrongSAN(t *testing.T) {
	for sanName, dns := range wrongSANs {
		persisted := func(t *testing.T) *renewalHarness {
			h := newRenewalHarness(t, harnessIssued)
			wrong := buildServerCertWithSAN(t, harnessIssued, h.caCert, h.caKey, &h.srvOpen.key.PublicKey, dns)
			h.write(serverCertFile, wrong.Raw)
			h.leaf = wrong
			h.now = harnessIssued.Add(time.Hour)
			return h
		}
		assertUnchanged := func(h *renewalHarness) {
			h.t.Helper()
			h.assertSignersReleased()
			if h.tempMade != 0 || h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
				h.t.Fatal("a SAN rejection must not write")
			}
		}

		t.Run(sanName+"/serving", func(t *testing.T) {
			h := persisted(t)
			m, err := loadServing(h.env())
			assertSANRejected(t, err)
			if m.ServerCertificate != nil {
				t.Fatal("a failure must return a zero Material")
			}
			assertUnchanged(h)
		})

		for _, policy := range []reloadPolicy{reportRenewalDue, verifyExistingState} {
			t.Run(sanName+"/reload policy "+map[reloadPolicy]string{reportRenewalDue: "ReloadMachine", verifyExistingState: "provisioning"}[policy], func(t *testing.T) {
				h := persisted(t)
				m, err := reloadExisting(h.env(), policy)
				assertSANRejected(t, err)
				if m.ServerCertificate != nil {
					t.Fatal("a failure must return a zero Material")
				}
				assertUnchanged(h)
			})
		}

		t.Run(sanName+"/existing-state provisioning", func(t *testing.T) {
			h := persisted(t)
			dataDir := provisionDataDir(h)
			before := dirSnapshot(t, dataDir)
			installs := 0
			_, err := ProvisionWithKeyStore(dataDir, &fixedKeyStore{ca: h.caKey, srv: h.srvOpen.key}, countingTrustStore(&installs), fixedNow(h.now))
			assertSANRejected(t, err)
			if after := dirSnapshot(t, dataDir); installs != 0 || !maps.Equal(before, after) {
				t.Fatal("existing-state provisioning must not write or install trust")
			}
		})

		t.Run(sanName+"/stage", func(t *testing.T) {
			h := persisted(t)
			h.now = h.due()
			_, err := stageServerRenewal(h.env())
			assertSANRejected(t, err)
			assertUnchanged(h)
		})

		// A wrong-SAN pending candidate, referenced by its own digest, is
		// rejected by candidate load and by Confirm, which promotes nothing.
		candidate := func(t *testing.T) (*renewalHarness, CandidateRef) {
			h := newRenewalHarness(t, harnessIssued)
			h.now = h.due()
			ref := h.stage()
			wrong := buildServerCertWithSAN(t, h.now, h.caCert, h.caKey, &h.srvOpen.key.PublicKey, dns)
			h.write(pendingServerCertFile, wrong.Raw)
			ref.CandidateSHA256 = sha256.Sum256(wrong.Raw)
			h.tempMade = 0
			return h, ref
		}

		t.Run(sanName+"/candidate load", func(t *testing.T) {
			h, ref := candidate(t)
			m, err := loadServingCandidate(h.env(), ref)
			assertSANRejected(t, err)
			if m.ServerCertificate != nil {
				t.Fatal("a failure must return a zero Material")
			}
			h.assertSignersReleased()
		})

		t.Run(sanName+"/confirm", func(t *testing.T) {
			h, ref := candidate(t)
			pending := h.read(pendingServerCertFile)
			assertSANRejected(t, confirmServingCandidate(h.env(), ref))
			h.assertSignersReleased()
			if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || h.read(prevServerCertFile) != nil ||
				!bytes.Equal(h.read(pendingServerCertFile), pending) || h.tempMade != 0 {
				t.Fatal("a rejected Confirm must not back up, promote or change the pending candidate")
			}
		})
	}
}
