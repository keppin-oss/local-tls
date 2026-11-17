package localtls

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Offline tests for the CA name constraints and EKU.
// They prove what Go's verifier does with the constraints; behaviour of
// Schannel/CryptoAPI, .NET and browsers is not covered here (live validation is
// a separate step).

var caTestNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// caVariant builds a self-signed CA for key with the production subject and
// validity. The mutate callback edits the template so each test controls
// exactly which constraint or EKU is present.
func caVariant(t *testing.T, key crypto.Signer, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCN, Organization: []string{caOrg}},
		NotBefore:             caTestNow.Add(-5 * time.Minute),
		NotAfter:              caTestNow.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// constrained applies the production constraints and EKU to a template.
func constrained(c *x509.Certificate) {
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	c.PermittedDNSDomainsCritical = true
	c.PermittedDNSDomains = []string{"localhost"}
	c.PermittedIPRanges = caPermittedIPRanges()
}

// anyLeaf issues a leaf for arbitrary names and EKU, valid for key, signature
// and time, so that a failure can only come from the CA constraints or EKU.
func anyLeaf(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, dns []string, ips []net.IP, eku []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverCN, Organization: []string{serverOrg}},
		NotBefore:    caTestNow.Add(-5 * time.Minute),
		NotAfter:     caTestNow.Add(serverValidity),
		DNSNames:     dns,
		IPAddresses:  ips,
		ExtKeyUsage:  eku,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &mustKey(t).PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func verifyAgainst(leaf, ca *x509.Certificate, dnsName string, usages []x509.ExtKeyUsage) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: dnsName, CurrentTime: caTestNow, KeyUsages: usages})
	return err
}

var (
	serverAuthOnly = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	loopbackIPs    = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
)

func TestCATemplateHasConstraintsAndEKU(t *testing.T) {
	ca, err := generateCAWithSigner(caTestNow, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if !ca.PermittedDNSDomainsCritical {
		t.Error("name constraints are not marked critical")
	}
	if len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != "localhost" {
		t.Errorf("permitted DNS = %v, want [localhost]", ca.PermittedDNSDomains)
	}
	got := map[string]bool{}
	for _, n := range ca.PermittedIPRanges {
		got[n.String()] = true
	}
	if len(got) != 2 || !got["127.0.0.1/32"] || !got["::1/128"] {
		t.Errorf("permitted IP ranges = %v, want exactly 127.0.0.1/32 and ::1/128 (not 127.0.0.0/8)", got)
	}
	if len(ca.ExcludedDNSDomains)+len(ca.ExcludedIPRanges)+len(ca.PermittedEmailAddresses)+len(ca.PermittedURIDomains) != 0 {
		t.Error("unexpected extra constraints")
	}
	if len(ca.ExtKeyUsage) != 1 || ca.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(ca.UnknownExtKeyUsage) != 0 {
		t.Errorf("CA EKU = %v, want [serverAuth]", ca.ExtKeyUsage)
	}
	if err := validateCA(ca, caTestNow); err != nil {
		t.Fatalf("validateCA rejects a freshly generated CA: %v", err)
	}
}

func TestLeafAcceptedByConstrainedCA(t *testing.T) {
	key := mustKey(t)
	ca, err := generateCAWithSigner(caTestNow, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := generateServerCertWithSigner(caTestNow, ca, key, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := verifyAgainst(leaf, ca, name, serverAuthOnly); err != nil {
			t.Errorf("leaf for %s rejected: %v", name, err)
		}
	}
	if err := validateServerLeaf(leaf, ca, leaf.PublicKey, caTestNow); err != nil {
		t.Errorf("validateServerLeaf: %v", err)
	}
	// Renewal: a second leaf under the same CA is accepted the same way.
	renewed, err := generateServerCertWithSigner(caTestNow.Add(61*24*time.Hour), ca, key, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateServerLeaf(renewed, ca, renewed.PublicKey, caTestNow.Add(61*24*time.Hour)); err != nil {
		t.Errorf("renewed leaf rejected: %v", err)
	}
}

// TestOutOfConstraintLeafRejectedByConstraints isolates the cause: the same
// leaf (valid key, signature, time, EKU and requested hostname) verifies
// against an unconstrained control CA with the same key and fails only against
// the constrained CA.
func TestOutOfConstraintLeafRejectedByConstraints(t *testing.T) {
	key := mustKey(t)
	good := caVariant(t, key, constrained)
	control := caVariant(t, key, func(c *x509.Certificate) { c.ExtKeyUsage = serverAuthOnly })

	cases := []struct {
		name string
		dns  []string
		ips  []net.IP
		ask  string
	}{
		{"external DNS", []string{"example.com"}, nil, "example.com"},
		{"external IP", nil, []net.IP{net.IPv4(10, 0, 0, 1)}, "10.0.0.1"},
		{"other loopback IP", nil, []net.IP{net.IPv4(127, 0, 0, 2)}, "127.0.0.2"},
		{"mixed allowed and forbidden", []string{"localhost", "example.com"}, nil, "localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := anyLeaf(t, good, key, tc.dns, tc.ips, serverAuthOnly)
			if err := verifyAgainst(leaf, control, tc.ask, serverAuthOnly); err != nil {
				t.Fatalf("control (unconstrained CA) rejects the leaf, so the test does not isolate the constraints: %v", err)
			}
			err := verifyAgainst(leaf, good, tc.ask, serverAuthOnly)
			var inv x509.CertificateInvalidError
			if !errors.As(err, &inv) || inv.Reason != x509.CANotAuthorizedForThisName {
				t.Fatalf("err = %v, want CANotAuthorizedForThisName", err)
			}
		})
	}
}

func TestSubdomainOfLocalhostAllowedByConstraintOnly(t *testing.T) {
	key := mustKey(t)
	good := caVariant(t, key, constrained)
	leaf := anyLeaf(t, good, key, []string{"foo.localhost"}, nil, serverAuthOnly)
	if err := verifyAgainst(leaf, good, "foo.localhost", serverAuthOnly); err != nil {
		t.Fatalf("foo.localhost rejected by the DNS constraint: %v (the constraint is a subtree)", err)
	}
	if err := validateSAN(leaf); err == nil {
		t.Fatal("validateSAN accepted foo.localhost")
	}
}

func TestCAEKURejectsNonTLSUsage(t *testing.T) {
	key := mustKey(t)
	good := caVariant(t, key, constrained)
	control := caVariant(t, key, func(c *x509.Certificate) {
		constrained(c)
		c.ExtKeyUsage = nil
	})
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	leaf := anyLeaf(t, good, key, []string{"localhost"}, nil, both)
	clientAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if err := verifyAgainst(leaf, control, "localhost", clientAuth); err != nil {
		t.Fatalf("control CA without EKU rejects the client-auth use: %v", err)
	}
	err := verifyAgainst(leaf, good, "localhost", clientAuth)
	var inv x509.CertificateInvalidError
	if !errors.As(err, &inv) || inv.Reason != x509.IncompatibleUsage {
		t.Fatalf("err = %v, want IncompatibleUsage", err)
	}
}

func TestValidateCARejectsMissingOrWrongConstraints(t *testing.T) {
	key := mustKey(t)
	cases := []struct {
		name   string
		mutate func(*x509.Certificate)
		ok     bool
	}{
		{"new CA", constrained, true},
		{"no constraints, no EKU", nil, false},
		{"no constraints, EKU serverAuth", func(c *x509.Certificate) { c.ExtKeyUsage = serverAuthOnly }, false},
		{"constraints, no EKU", func(c *x509.Certificate) { constrained(c); c.ExtKeyUsage = nil }, false},
		{"constraints, EKU clientAuth", func(c *x509.Certificate) {
			constrained(c)
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}, false},
		{"constraints, EKU serverAuth+clientAuth", func(c *x509.Certificate) {
			constrained(c)
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}, false},
		{"constraints not critical", func(c *x509.Certificate) { constrained(c); c.PermittedDNSDomainsCritical = false }, false},
		{"wider IP range 127.0.0.0/8", func(c *x509.Certificate) {
			constrained(c)
			c.PermittedIPRanges = []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
				{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
			}
		}, false},
		{"IPv6 range missing", func(c *x509.Certificate) { constrained(c); c.PermittedIPRanges = c.PermittedIPRanges[:1] }, false},
		{"IP ranges in reverse order", func(c *x509.Certificate) {
			constrained(c)
			r := caPermittedIPRanges()
			c.PermittedIPRanges = []*net.IPNet{r[1], r[0]}
		}, true},
		{"duplicated IP range", func(c *x509.Certificate) {
			constrained(c)
			r := caPermittedIPRanges()
			c.PermittedIPRanges = []*net.IPNet{r[0], r[0]}
		}, false},
		{"extra IP range", func(c *x509.Certificate) {
			constrained(c)
			c.PermittedIPRanges = append(c.PermittedIPRanges, &net.IPNet{IP: net.IPv4(127, 0, 0, 2).To4(), Mask: net.CIDRMask(32, 32)})
		}, false},
		{"excluded email constraint", func(c *x509.Certificate) { constrained(c); c.ExcludedEmailAddresses = []string{"example.com"} }, false},
		{"excluded URI constraint", func(c *x509.Certificate) { constrained(c); c.ExcludedURIDomains = []string{"example.com"} }, false},
		{"extra DNS domain", func(c *x509.Certificate) {
			constrained(c)
			c.PermittedDNSDomains = []string{"localhost", "example.com"}
		}, false},
		{"other DNS domain", func(c *x509.Certificate) { constrained(c); c.PermittedDNSDomains = []string{"example.com"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := caVariant(t, key, tc.mutate)
			err := validateCA(ca, caTestNow)
			if tc.ok {
				if err != nil {
					t.Fatalf("validateCA: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrCANotConstrained) {
				t.Fatalf("err = %v, want ErrCANotConstrained", err)
			}
			if errors.Is(err, ErrCertificateNotValidNow) || errors.Is(err, ErrTrustNotHealthy) {
				t.Fatalf("rejection is confusable with an expired CA or unhealthy trust: %v", err)
			}
		})
	}
}

// legacyHarness replaces the harness CA and leaf with an unconstrained CA that
// uses the same key, as an earlier development build would have persisted.
func legacyHarness(t *testing.T) *renewalHarness {
	t.Helper()
	h := newRenewalHarness(t, harnessIssued)
	legacy := caVariant(t, h.caKey, func(c *x509.Certificate) {
		c.NotBefore = harnessIssued.Add(-5 * time.Minute)
		c.NotAfter = harnessIssued.Add(caValidity)
	})
	leaf, err := generateServerCertWithSigner(harnessIssued, legacy, h.caKey, h.srvOpen.key)
	if err != nil {
		t.Fatal(err)
	}
	h.caCert, h.leaf = legacy, leaf
	h.write(caCertFile, legacy.Raw)
	h.write(serverCertFile, leaf.Raw)
	return h
}

// TestUnconstrainedCARejectedOnServingAndRenewalPaths covers the callers in
// renewal.go that validate the CA: serving, stage, candidate load and confirm.
// Nothing is regenerated or rewritten, no pending candidate is written or
// promoted, and the signers are released.
func TestUnconstrainedCARejectedOnServingAndRenewalPaths(t *testing.T) {
	t.Run("serving", func(t *testing.T) {
		h := legacyHarness(t)
		caBefore := h.read(caCertFile)
		if _, err := loadServing(h.env()); !errors.Is(err, ErrCANotConstrained) {
			t.Fatalf("err = %v, want ErrCANotConstrained", err)
		}
		if !bytes.Equal(h.read(caCertFile), caBefore) {
			t.Fatal("CA DER was rewritten")
		}
		h.assertSignersReleased()
	})
	t.Run("candidate load and confirm", func(t *testing.T) {
		h := legacyHarness(t)
		h.now = h.due()
		pending, err := generateServerCertWithSigner(h.now, h.caCert, h.caKey, h.srvOpen.key)
		if err != nil {
			t.Fatal(err)
		}
		h.write(pendingServerCertFile, pending.Raw)
		// Hashes are coherent, so a rejection cannot come from a stale or
		// mismatching reference.
		ref := CandidateRef{
			Outcome:         RenewalCandidateStaged,
			CandidateSHA256: sha256.Sum256(pending.Raw),
			BaseSHA256:      sha256.Sum256(h.leaf.Raw),
			CASHA256:        sha256.Sum256(h.caCert.Raw),
		}
		snap := map[string][]byte{}
		for _, n := range []string{caCertFile, serverCertFile, pendingServerCertFile, prevServerCertFile} {
			snap[n] = h.read(n)
		}
		if _, err := loadServingCandidate(h.env(), ref); !errors.Is(err, ErrCANotConstrained) {
			t.Fatalf("load: err = %v, want ErrCANotConstrained", err)
		}
		if err := confirmServingCandidate(h.env(), ref); !errors.Is(err, ErrCANotConstrained) {
			t.Fatalf("confirm: err = %v, want ErrCANotConstrained", err)
		}
		for n, want := range snap {
			if !bytes.Equal(h.read(n), want) {
				t.Fatalf("%s changed", n)
			}
		}
		if snap[prevServerCertFile] != nil {
			t.Fatal("a backup was written")
		}
		h.assertSignersReleased()
		h.assertNoTemps()
	})
	t.Run("stage renewal", func(t *testing.T) {
		h := legacyHarness(t)
		h.now = h.due()
		caBefore, leafBefore := h.read(caCertFile), h.read(serverCertFile)
		if _, err := stageServerRenewal(h.env()); !errors.Is(err, ErrCANotConstrained) {
			t.Fatalf("err = %v, want ErrCANotConstrained", err)
		}
		if h.read(pendingServerCertFile) != nil || !bytes.Equal(h.read(caCertFile), caBefore) || !bytes.Equal(h.read(serverCertFile), leafBefore) {
			t.Fatal("a rejected CA must not cause any write")
		}
		h.assertSignersReleased()
	})
}

// TestExistingStateProvisioningRejectsUnconstrainedCA covers
// ProvisionWithKeyStore on existing state: the CA is rejected, not
// regenerated, and trust is not touched. The full production sequence,
// including the pre-checks, is covered by the Windows test
// TestProvisionMachineRejectsUnconstrainedCA.
func TestExistingStateProvisioningRejectsUnconstrainedCA(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	tlsDir := filepath.Join(dataDir, tlsSubDir)
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
	ks := fakeMachineKeyStore{simulateExistingCA: true, simulateExistingServer: true, caSigner: caSigner, serverSigner: serverSigner}
	installs := 0
	_, err = ProvisionWithKeyStore(dataDir, ks, countingTrustStore(&installs), fixedNow(caTestNow))
	if !errors.Is(err, ErrCANotConstrained) {
		t.Fatalf("err = %v, want ErrCANotConstrained", err)
	}
	if installs != 0 {
		t.Fatal("trust was installed for a rejected CA")
	}
	got, readErr := os.ReadFile(filepath.Join(tlsDir, caCertFile))
	if readErr != nil || !bytes.Equal(got, legacy.Raw) {
		t.Fatal("CA DER was replaced or removed")
	}
}
