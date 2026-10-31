package localtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConsumer is an in-memory stand-in for a consumer listener and its
// coordinator. It is a test device only: it models the consumer-owned
// activation and attestation steps of the renewal protocol and does not
// represent any existing production consumer.
type fakeConsumer struct {
	mu      sync.Mutex
	serving Material

	failActivate   bool // activation fails before swapping
	ignoreActivate bool // activation reports success without swapping
}

func (c *fakeConsumer) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			cert := c.serving.Certificate
			return &cert, nil
		},
	}
}

func (c *fakeConsumer) activate(m Material) error {
	if c.failActivate {
		return errors.New("fake consumer: activation failed")
	}
	if c.ignoreActivate {
		return nil
	}
	c.mu.Lock()
	c.serving = m
	c.mu.Unlock()
	return nil
}

func (c *fakeConsumer) restore(m Material) {
	c.mu.Lock()
	c.serving = m
	c.mu.Unlock()
}

// attest performs a fresh, full (non-resumed) handshake against the listener
// over an in-memory pipe, verifying chain and name against ca, and returns the
// SHA-256 of the leaf the client actually observed.
func (c *fakeConsumer) attest(ca *x509.Certificate, now time.Time) ([32]byte, error) {
	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()
	go func() {
		s := tls.Server(srvConn, c.tlsConfig())
		_ = s.Handshake()
		s.Close()
	}()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cli := tls.Client(cliConn, &tls.Config{
		RootCAs:                roots,
		ServerName:             "localhost",
		Time:                   func() time.Time { return now },
		SessionTicketsDisabled: true,
	})
	if err := cli.Handshake(); err != nil {
		return [32]byte{}, err
	}
	st := cli.ConnectionState()
	if st.DidResume || len(st.PeerCertificates) == 0 {
		return [32]byte{}, errors.New("handshake resumed or presented no certificate")
	}
	return sha256.Sum256(st.PeerCertificates[0].Raw), nil
}

var errNotAttested = errors.New("consumer could not attest the candidate")

// renewOnce is the fake coordinator: stage → load → activate → attest →
// confirm, or restore + abandon. Old Material stays open until it can no
// longer be needed for rollback.
func renewOnce(h *renewalHarness, c *fakeConsumer) error {
	ref, err := stageServerRenewal(h.env())
	if err != nil || ref.Outcome != RenewalCandidateStaged {
		return err
	}
	cand, err := loadServingCandidate(h.env(), ref)
	if err != nil {
		return err
	}
	old := c.serving
	rollback := func(cause error) error {
		c.restore(old)
		if fp, err := c.attest(h.caCert, h.now); err != nil || fp != sha256.Sum256(old.ServerCertificate.Raw) {
			return errors.Join(cause, errors.New("rollback could not be verified"))
		}
		cand.Close()
		return errors.Join(cause, abandonServingCandidate(h.env(), ref))
	}
	if err := c.activate(cand); err != nil {
		return rollback(err)
	}
	fp, err := c.attest(h.caCert, h.now)
	if err != nil {
		return rollback(err)
	}
	if fp != ref.CandidateSHA256 {
		return rollback(errNotAttested)
	}
	if err := confirmServingCandidate(h.env(), ref); err != nil {
		return err
	}
	old.Close()
	return nil
}

func newConsumerHarness(t *testing.T) (*renewalHarness, *fakeConsumer) {
	t.Helper()
	h := newRenewalHarness(t, harnessIssued)
	h.now = h.due()
	m, err := loadServing(h.env())
	if err != nil {
		t.Fatalf("initial serving material: %v", err)
	}
	return h, &fakeConsumer{serving: m}
}

func TestFakeConsumerAttestedRenewalPromotes(t *testing.T) {
	h, c := newConsumerHarness(t)
	if err := renewOnce(h, c); err != nil {
		t.Fatalf("renew: %v", err)
	}
	fp, err := c.attest(h.caCert, h.now)
	if err != nil {
		t.Fatal(err)
	}
	if fp != sha256.Sum256(h.read(serverCertFile)) || bytes.Equal(h.read(serverCertFile), h.leaf.Raw) {
		t.Fatal("persisted certificate must be the attested candidate")
	}
	if !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("backup must hold the previous certificate")
	}
	if n := h.srvOpen.unclosed(); n != 1 {
		t.Fatalf("%d server signers open, want exactly the one now serving", n)
	}
}

func TestFakeConsumerFailedActivationAbandons(t *testing.T) {
	for name, configure := range map[string]func(c *fakeConsumer){
		"activation error":              func(c *fakeConsumer) { c.failActivate = true },
		"activation reported but no-op": func(c *fakeConsumer) { c.ignoreActivate = true },
	} {
		t.Run(name, func(t *testing.T) {
			h, c := newConsumerHarness(t)
			configure(c)
			err := renewOnce(h, c)
			if err == nil {
				t.Fatal("renewal without attested activation must not succeed")
			}
			if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || h.read(prevServerCertFile) != nil {
				t.Fatal("an unattested candidate must never be promoted")
			}
			if h.read(pendingServerCertFile) != nil {
				t.Fatal("the consumer abandoned the candidate after restoring the old material")
			}
			fp, aerr := c.attest(h.caCert, h.now)
			if aerr != nil || fp != sha256.Sum256(h.leaf.Raw) {
				t.Fatal("the listener must still serve the previous certificate")
			}
			if n := h.srvOpen.unclosed(); n != 1 {
				t.Fatalf("%d server signers open, want exactly the one still serving", n)
			}
		})
	}
}
