package localtls

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// firstInstallFixture runs a first install on a fresh data directory with an
// in-memory key store, returning what the test needs to check the outcome.
type firstInstallFixture struct {
	dataDir string
	tlsDir  string
	keys    *fakeMachineKeyStore
	trust   *fakeTrustStore
}

func newFirstInstallFixture(t *testing.T) *firstInstallFixture {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	return &firstInstallFixture{
		dataDir: dataDir,
		tlsDir:  filepath.Join(dataDir, tlsSubDir),
		keys:    newFakeMachineKeyStore(false, false),
		trust:   okTrustStore(),
	}
}

func (f *firstInstallFixture) run() (Material, error) {
	return ProvisionWithKeyStore(f.dataDir, f.keys, f.trust, fixedNow(time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)))
}

func spkiOf(t *testing.T, s crypto.Signer) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func (f *firstInstallFixture) assertNoDER(t *testing.T) {
	t.Helper()
	for _, name := range []string{caCertFile, serverCertFile} {
		if fileExists(filepath.Join(f.tlsDir, name)) {
			t.Fatalf("%s left behind by a failed first install", name)
		}
	}
}

// assertDeleted checks which keys the rollback deleted, each with exactly the
// SPKI of the key the install created.
func (f *firstInstallFixture) assertDeleted(t *testing.T, ca, server bool) {
	t.Helper()
	check := func(role string, want bool, got [][]byte, signer crypto.Signer) {
		switch {
		case !want && len(got) != 0:
			t.Fatalf("%s key deleted %d time(s), want none", role, len(got))
		case want && (len(got) != 1 || !bytes.Equal(got[0], spkiOf(t, signer))):
			t.Fatalf("%s key deletes %x, want one with its recorded SPKI", role, got)
		}
	}
	check("CA", ca, f.keys.caDeletes, f.keys.caSigner)
	check("server", server, f.keys.serverDeletes, f.keys.serverSigner)
}

// TestFirstInstallCreatesBothKeys proves the first install creates both keys
// once, never opens one, and persists both DERs.
func TestFirstInstallCreatesBothKeys(t *testing.T) {
	f := newFirstInstallFixture(t)
	counting := &countingKeyStore{inner: f.keys}
	m, err := ProvisionWithKeyStore(f.dataDir, counting, f.trust, fixedNow(time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	defer m.Close()
	if f.keys.caCreates != 1 || f.keys.serverCreates != 1 || counting.creates != 2 || counting.caCalls+counting.srCalls != 2 {
		t.Fatalf("creates CA=%d server=%d, acquisitions %d; want one create each and no open", f.keys.caCreates, f.keys.serverCreates, counting.caCalls+counting.srCalls)
	}
	if !bytes.Equal(m.CACertificate.RawSubjectPublicKeyInfo, spkiOf(t, f.keys.caSigner)) ||
		!bytes.Equal(m.ServerCertificate.RawSubjectPublicKeyInfo, spkiOf(t, f.keys.serverSigner)) {
		t.Fatal("the persisted certificates do not record the created keys")
	}
}

// TestFirstInstallExistingCAKeyIsNotAdopted proves that a CA key already
// persisted under the name fails the first install with ErrKeyExists: it is
// not adopted, certified or deleted, and nothing else is created.
func TestFirstInstallExistingCAKeyIsNotAdopted(t *testing.T) {
	f := newFirstInstallFixture(t)
	f.keys.simulateExistingCA = true
	_, err := f.run()
	if !errors.Is(err, ErrKeyExists) {
		t.Fatalf("err = %v, want ErrKeyExists", err)
	}
	if errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("nothing was created, so nothing is left to roll back: %v", err)
	}
	if f.keys.serverCreates != 0 || !f.keys.simulateExistingCA {
		t.Fatal("the existing CA key was touched or the server key was created")
	}
	f.assertDeleted(t, false, false)
	f.assertNoDER(t)
}

// TestFirstInstallServerCreateFailureRollsBackCAOnly proves that when the
// server key cannot be created (it already exists, or the create fails), only
// the CA key created by this call is deleted, with its recorded SPKI, and an
// existing server key is left untouched.
func TestFirstInstallServerCreateFailureRollsBackCAOnly(t *testing.T) {
	createFailed := errors.New("NCryptFinalizeKey: hr=0x80090010")
	for _, tc := range []struct {
		name   string
		setup  func(*fakeMachineKeyStore)
		wantIs error
	}{
		{"server key exists", func(k *fakeMachineKeyStore) { k.simulateExistingServer = true }, ErrKeyExists},
		{"server create fails", func(k *fakeMachineKeyStore) { k.serverCreateErr = createFailed }, createFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFirstInstallFixture(t)
			tc.setup(f.keys)
			existedBefore := f.keys.simulateExistingServer
			_, err := f.run()
			if !errors.Is(err, tc.wantIs) || errors.Is(err, ErrRollbackIncomplete) {
				t.Fatalf("err = %v, want %v and a complete rollback", err, tc.wantIs)
			}
			f.assertDeleted(t, true, false)
			if f.keys.simulateExistingCA {
				t.Fatal("the CA key created by this call still exists")
			}
			if f.keys.simulateExistingServer != existedBefore {
				t.Fatal("the server key was modified")
			}
			f.assertNoDER(t)
		})
	}
}

// TestFirstInstallDERWriteFailureRollsBack proves that a failure to persist
// either DER removes what this call wrote and deletes both created keys.
func TestFirstInstallDERWriteFailureRollsBack(t *testing.T) {
	for _, failing := range []string{caCertFile, serverCertFile} {
		t.Run(failing, func(t *testing.T) {
			saved := osFS
			t.Cleanup(func() { osFS = saved })
			writeErr := errors.New("disk full")
			osFS.replace = func(oldpath, newpath string) error {
				if filepath.Base(newpath) == failing {
					return writeErr
				}
				return saved.replace(oldpath, newpath)
			}
			f := newFirstInstallFixture(t)
			_, err := f.run()
			if !errors.Is(err, writeErr) || errors.Is(err, ErrRollbackIncomplete) {
				t.Fatalf("err = %v, want the write error and a complete rollback", err)
			}
			f.assertDeleted(t, true, true)
			f.assertNoDER(t)
		})
	}
}

// TestFirstInstallReplaceErrorAfterEffectIsRolledBack proves that a DER whose
// replace reported an error after taking effect is still removed.
func TestFirstInstallReplaceErrorAfterEffectIsRolledBack(t *testing.T) {
	saved := osFS
	t.Cleanup(func() { osFS = saved })
	lateErr := errors.New("replace reported a failure after the rename")
	osFS.replace = func(oldpath, newpath string) error {
		if err := saved.replace(oldpath, newpath); err != nil {
			return err
		}
		if filepath.Base(newpath) == serverCertFile {
			return lateErr
		}
		return nil
	}
	f := newFirstInstallFixture(t)
	if _, err := f.run(); !errors.Is(err, lateErr) || errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("err = %v, want the late error and a complete rollback", err)
	}
	f.assertDeleted(t, true, true)
	f.assertNoDER(t)
}

// unencodableSigner is a signer whose public key x509 cannot encode.
type unencodableSigner struct{}

func (unencodableSigner) Public() crypto.PublicKey { return struct{}{} }
func (unencodableSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unencodableSigner cannot sign")
}

// TestFirstInstallUnrecordableKeyIsNotDeleted proves that a created key whose
// SPKI cannot be encoded is never deleted (there is no identity to verify),
// that the other created key is, and that the error says the rollback is
// incomplete and why.
func TestFirstInstallUnrecordableKeyIsNotDeleted(t *testing.T) {
	t.Run("CA", func(t *testing.T) {
		f := newFirstInstallFixture(t)
		f.keys.caSigner = unencodableSigner{}
		_, err := f.run()
		if !errors.Is(err, ErrRollbackIncomplete) || !errors.Is(err, ErrKeyDeletionNotCompletable) {
			t.Fatalf("err = %v, want ErrRollbackIncomplete and ErrKeyDeletionNotCompletable", err)
		}
		if len(f.keys.caDeletes) != 0 || !f.keys.simulateExistingCA || f.keys.serverCreates != 0 {
			t.Fatal("an unrecorded CA key was deleted, or the install went on to the server key")
		}
		f.assertNoDER(t)
	})
	t.Run("server", func(t *testing.T) {
		f := newFirstInstallFixture(t)
		f.keys.serverSigner = unencodableSigner{}
		_, err := f.run()
		if !errors.Is(err, ErrRollbackIncomplete) || !errors.Is(err, ErrKeyDeletionNotCompletable) || !strings.Contains(err.Error(), "server key") {
			t.Fatalf("err = %v, want a not-completable server key deletion", err)
		}
		if len(f.keys.serverDeletes) != 0 || !f.keys.simulateExistingServer {
			t.Fatal("an unrecorded server key was deleted")
		}
		if len(f.keys.caDeletes) != 1 || f.keys.simulateExistingCA {
			t.Fatal("the recorded CA key was not deleted")
		}
		f.assertNoDER(t)
	})
}

// TestFirstInstallRollbackDeleteFailureIsReported proves that a failed
// compensating delete keeps the primary failure and the delete failure, names
// the key by the SHA-256 of its SPKI, and still attempts the other delete.
func TestFirstInstallRollbackDeleteFailureIsReported(t *testing.T) {
	saved := osFS
	t.Cleanup(func() { osFS = saved })
	writeErr := errors.New("disk full")
	osFS.replace = func(string, string) error { return writeErr }

	f := newFirstInstallFixture(t)
	deleteErr := fmt.Errorf("NCryptDeleteKey: %w", ErrKeyNotFound)
	f.keys.serverDeleteErr = deleteErr
	_, err := f.run()
	for _, want := range []error{writeErr, ErrRollbackIncomplete, ErrKeyNotFound} {
		if !errors.Is(err, want) {
			t.Fatalf("err = %v, want it to match %v", err, want)
		}
	}
	serverSPKI := spkiOf(t, f.keys.serverSigner)
	if !strings.Contains(err.Error(), fmt.Sprintf("%x", sha256.Sum256(serverSPKI))) {
		t.Fatalf("err = %v does not identify the key left behind", err)
	}
	f.assertDeleted(t, true, false)
}

// TestFirstInstallTrustFailureIsNotRolledBack proves the compensation
// boundary: once both DERs are persisted, a trust installation failure leaves
// the keys and DERs in place (CleanupMachine removes them) and releases both
// signers.
func TestFirstInstallTrustFailureIsNotRolledBack(t *testing.T) {
	f := newFirstInstallFixture(t)
	trustErr := errors.New("CertAddEncodedCertificateToStore: access denied")
	f.trust.install = func([]byte) error { return trustErr }
	ks := &closeTrackingKeyStore{caSigner: newFakeCloseSigner(), serverSigner: newFakeCloseSigner()}
	_, err := ProvisionWithKeyStore(f.dataDir, ks, f.trust, fixedNow(time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)))
	if !errors.Is(err, trustErr) || errors.Is(err, ErrRollbackIncomplete) || !strings.Contains(err.Error(), "CleanupMachine") {
		t.Fatalf("err = %v, want the trust error pointing to CleanupMachine", err)
	}
	if ks.deleteCA+ks.deleteServer != 0 {
		t.Fatal("keys were deleted after both DERs were persisted")
	}
	for _, name := range []string{caCertFile, serverCertFile} {
		if !fileExists(filepath.Join(f.tlsDir, name)) {
			t.Fatalf("%s removed after a trust failure", name)
		}
	}
	if !ks.caSigner.closed || !ks.serverSigner.closed {
		t.Fatal("both signers must be released on failure")
	}
	if _, err := os.Stat(f.tlsDir); err != nil {
		t.Fatal(err)
	}
}

// eventLog records the Close and Delete calls of a first install, in order.
type eventLog struct{ events []string }

func (l *eventLog) add(e string) { l.events = append(l.events, e) }

// loggingSigner is an in-memory signer whose Close is logged and can fail.
type loggingSigner struct {
	crypto.Signer
	role     string
	log      *eventLog
	closeErr error
	closes   int
}

func (s *loggingSigner) Close() error {
	s.closes++
	s.log.add("close:" + s.role)
	return s.closeErr
}

// loggingKeyStore logs the deletes of a fakeMachineKeyStore in the same log as
// the signers' Close calls.
type loggingKeyStore struct {
	*fakeMachineKeyStore
	log *eventLog
}

func (k loggingKeyStore) DeleteCAKey(spki []byte) error {
	k.log.add("delete:CA")
	return k.fakeMachineKeyStore.DeleteCAKey(spki)
}

func (k loggingKeyStore) DeleteServerKey(spki []byte) error {
	k.log.add("delete:server")
	return k.fakeMachineKeyStore.DeleteServerKey(spki)
}

// newLoggingFixture wraps the fixture's signers and deletes in one event log.
func newLoggingFixture(t *testing.T) (*firstInstallFixture, *eventLog, *loggingSigner, *loggingSigner, loggingKeyStore) {
	t.Helper()
	f := newFirstInstallFixture(t)
	log := &eventLog{}
	ca := &loggingSigner{Signer: f.keys.caSigner, role: "CA", log: log}
	srv := &loggingSigner{Signer: f.keys.serverSigner, role: "server", log: log}
	f.keys.caSigner, f.keys.serverSigner = ca, srv
	return f, log, ca, srv, loggingKeyStore{fakeMachineKeyStore: f.keys, log: log}
}

func (f *firstInstallFixture) runWith(ks MachineKeyStore) (Material, error) {
	return ProvisionWithKeyStore(f.dataDir, ks, f.trust, fixedNow(time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)))
}

// TestFirstInstallRollbackReleasesBeforeDelete proves the rollback order:
// every handle is released once, server then CA, before any delete, and the
// deletes follow, server then CA.
func TestFirstInstallRollbackReleasesBeforeDelete(t *testing.T) {
	saved := osFS
	t.Cleanup(func() { osFS = saved })
	writeErr := errors.New("disk full")
	osFS.replace = func(string, string) error { return writeErr }

	f, log, ca, srv, ks := newLoggingFixture(t)
	if _, err := f.runWith(ks); !errors.Is(err, writeErr) || errors.Is(err, ErrKeyReleaseUnconfirmed) {
		t.Fatalf("err = %v, want the write error only", err)
	}
	if got, want := strings.Join(log.events, ","), "close:server,close:CA,delete:server,delete:CA"; got != want {
		t.Fatalf("events %s, want %s", got, want)
	}
	if ca.closes != 1 || srv.closes != 1 {
		t.Fatalf("closes CA=%d server=%d, want 1/1", ca.closes, srv.closes)
	}
}

// TestFirstInstallRollbackReportsReleaseFailure proves that a handle whose
// release fails during the rollback is reported with its role, distinct from
// the delete outcome, is not closed again, and does not stop the verified
// delete of the key this call created.
func TestFirstInstallRollbackReportsReleaseFailure(t *testing.T) {
	f, log, ca, _, ks := newLoggingFixture(t)
	closeErr := errors.New("NCryptFreeObject failed")
	ca.closeErr = closeErr
	createErr := errors.New("server create failed")
	f.keys.serverCreateErr = createErr

	_, err := f.runWith(ks)
	for _, want := range []error{createErr, ErrKeyReleaseUnconfirmed, closeErr} {
		if !errors.Is(err, want) {
			t.Fatalf("err = %v, want it to match %v", err, want)
		}
	}
	if !strings.Contains(err.Error(), "release the CA key handle") {
		t.Fatalf("err = %v does not name the handle's role", err)
	}
	if errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("the delete succeeded, so the rollback is complete: %v", err)
	}
	if got, want := strings.Join(log.events, ","), "close:CA,delete:CA"; got != want {
		t.Fatalf("events %s, want %s", got, want)
	}
	if ca.closes != 1 {
		t.Fatalf("CA handle closed %d times, want exactly 1", ca.closes)
	}
}

// TestFirstInstallCAReleaseFailureStopsBeforeTrust proves that, once both
// DERs are persisted, a CA handle whose release is not confirmed stops the
// install before the trust anchor is installed: no Material, the server handle
// released, nothing rolled back.
func TestFirstInstallCAReleaseFailureStopsBeforeTrust(t *testing.T) {
	f, log, ca, srv, ks := newLoggingFixture(t)
	closeErr := errors.New("NCryptFreeObject failed")
	ca.closeErr = closeErr
	installs := 0
	f.trust.install = func([]byte) error { installs++; return nil }

	m, err := f.runWith(ks)
	if !errors.Is(err, ErrKeyReleaseUnconfirmed) || !errors.Is(err, closeErr) || !strings.Contains(err.Error(), "CleanupMachine") {
		t.Fatalf("err = %v, want an unconfirmed CA release pointing to CleanupMachine", err)
	}
	if m.Certificate.PrivateKey != nil || m.CACertificate != nil {
		t.Fatal("a failure must return a zero Material")
	}
	if installs != 0 {
		t.Fatal("the trust anchor was installed after an unconfirmed CA release")
	}
	if got, want := strings.Join(log.events, ","), "close:CA,close:server"; got != want {
		t.Fatalf("events %s, want %s (no delete after both DERs are persisted)", got, want)
	}
	if ca.closes != 1 || srv.closes != 1 {
		t.Fatalf("closes CA=%d server=%d, want 1/1", ca.closes, srv.closes)
	}
	for _, name := range []string{caCertFile, serverCertFile} {
		if !fileExists(filepath.Join(f.tlsDir, name)) {
			t.Fatalf("%s removed after both DERs were persisted", name)
		}
	}
}

// TestFirstInstallTrustFailureReportsServerRelease proves that a server handle
// whose release fails after a trust failure is reported with the trust error.
func TestFirstInstallTrustFailureReportsServerRelease(t *testing.T) {
	f, log, _, srv, ks := newLoggingFixture(t)
	trustErr := errors.New("CertAddEncodedCertificateToStore: access denied")
	closeErr := errors.New("NCryptFreeObject failed")
	f.trust.install = func([]byte) error { return trustErr }
	srv.closeErr = closeErr

	_, err := f.runWith(ks)
	for _, want := range []error{trustErr, ErrKeyReleaseUnconfirmed, closeErr} {
		if !errors.Is(err, want) {
			t.Fatalf("err = %v, want it to match %v", err, want)
		}
	}
	if !strings.Contains(err.Error(), "release the server key handle") {
		t.Fatalf("err = %v does not name the server handle", err)
	}
	if got, want := strings.Join(log.events, ","), "close:CA,close:server"; got != want {
		t.Fatalf("events %s, want %s", got, want)
	}
}
