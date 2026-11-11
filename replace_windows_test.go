//go:build windows

package localtls

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests run unprivileged in a per-test temporary directory. They touch
// no CNG key and no certificate store.

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReplaceFileWithReaderWithoutShareDelete proves that a reader opened the
// ordinary Go way (FILE_SHARE_READ|FILE_SHARE_WRITE, no FILE_SHARE_DELETE)
// makes the replace fail observably, leaving both files intact.
func TestReplaceFileWithReaderWithoutShareDelete(t *testing.T) {
	dir := t.TempDir()
	active, pending := filepath.Join(dir, "active"), filepath.Join(dir, "pending")
	writeTestFile(t, active, []byte("old"))
	writeTestFile(t, pending, []byte("new"))

	reader, err := os.Open(active)
	if err != nil {
		t.Fatal(err)
	}
	err = replaceFile(pending, active)
	reader.Close()
	if err == nil {
		t.Fatal("replace succeeded while a reader without FILE_SHARE_DELETE held the target")
	}
	t.Logf("replace with ordinary reader open: %v", err)
	if !bytes.Equal(readTestFile(t, active), []byte("old")) || !bytes.Equal(readTestFile(t, pending), []byte("new")) {
		t.Fatal("a failed replace must leave both files unchanged")
	}

	if err := replaceFile(pending, active); err != nil {
		t.Fatalf("replace after the reader closed: %v", err)
	}
	if !bytes.Equal(readTestFile(t, active), []byte("new")) {
		t.Fatal("replace did not install the new bytes")
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source must be gone after a successful replace")
	}
}

// TestReplaceFileWithShareDeleteReader records the platform behavior when the
// reader grants FILE_SHARE_DELETE. Either outcome is acceptable; the target
// must never be missing or hold anything but the old or the new bytes.
func TestReplaceFileWithShareDeleteReader(t *testing.T) {
	dir := t.TempDir()
	active, pending := filepath.Join(dir, "active"), filepath.Join(dir, "pending")
	writeTestFile(t, active, []byte("old"))
	writeTestFile(t, pending, []byte("new"))

	name, _ := windows.UTF16PtrFromString(active)
	h, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	rerr := replaceFile(pending, active)
	windows.CloseHandle(h)

	got := readTestFile(t, active)
	switch {
	case rerr == nil && bytes.Equal(got, []byte("new")):
		t.Log("replace succeeded while a FILE_SHARE_DELETE reader was open")
	case rerr != nil && bytes.Equal(got, []byte("old")):
		t.Logf("replace failed while a FILE_SHARE_DELETE reader was open: %v", rerr)
	default:
		t.Fatalf("inconsistent result: err=%v target=%q", rerr, got)
	}
}

// TestConfirmWhileServingReaderHoldsCertificate exercises the production file
// system: a promote that hits a sharing violation reports
// ErrPromotionUnconfirmed, changes nothing, and a retry succeeds with the
// original backup.
func TestConfirmWhileServingReaderHoldsCertificate(t *testing.T) {
	h := newRenewalHarness(t, harnessIssued)
	h.fs.replace = replaceFile
	h.now = h.due()
	ref := h.stage()
	cand := h.read(pendingServerCertFile)

	reader, err := os.Open(filepath.Join(h.dir, serverCertFile))
	if err != nil {
		t.Fatal(err)
	}
	err = confirmServingCandidate(h.env(), ref)
	reader.Close()
	if !errors.Is(err, ErrPromotionUnconfirmed) {
		t.Fatalf("err = %v, want ErrPromotionUnconfirmed", err)
	}
	if !bytes.Equal(h.read(serverCertFile), h.leaf.Raw) || !bytes.Equal(h.read(pendingServerCertFile), cand) {
		t.Fatal("a blocked promote must leave the persisted certificate and the candidate unchanged")
	}

	if err := confirmServingCandidate(h.env(), ref); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !bytes.Equal(h.read(serverCertFile), cand) || !bytes.Equal(h.read(prevServerCertFile), h.leaf.Raw) {
		t.Fatal("retry did not promote with the original backup")
	}
}

// TestRenewalPathsUseOpenOnlyKeys is a source check that the runtime and
// renewal composition opens existing CNG keys only and never routes through
// open-or-create; the policy-aware windowscng calls themselves stay in
// keystore_windows.go.
func TestRenewalPathsUseOpenOnlyKeys(t *testing.T) {
	src, err := os.ReadFile("composition_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := funcBody(string(src), "productionEnv")
	if !ok {
		t.Fatal("productionEnv not found")
	}
	if !strings.Contains(body, "openProductionKey(caKeyName)") || !strings.Contains(body, "openProductionKey(serverKeyName)") {
		t.Fatal("productionEnv must open the CA and server keys with openProductionKey")
	}
	if strings.Contains(body, "LoadOrCreate") || strings.Contains(body, "loadOrCreateKey") {
		t.Fatal("productionEnv must not create keys")
	}
	for _, f := range []string{"renewal.go", "validate.go", "fsops.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"windowscng", "LoadOrCreate", "InstallTrust", "Delete"} {
			if strings.Contains(string(b), forbidden) {
				t.Fatalf("%s must not reference %s", f, forbidden)
			}
		}
	}
}

// funcBody returns the source of the top-level function name, from its "func"
// keyword up to (excluding) its closing brace at column zero. Line endings are
// normalized to LF first, so LF and CRLF checkouts give the same result. It
// reports false when the function or its closing brace is not found.
func funcBody(src, name string) (string, bool) {
	s := strings.ReplaceAll(src, "\r\n", "\n")
	start := strings.Index(s, "func "+name+"(")
	if start < 0 {
		return "", false
	}
	end := strings.Index(s[start:], "\n}\n")
	if end < 0 {
		return "", false
	}
	return s[start : start+end], true
}

func TestFuncBodyLineEndings(t *testing.T) {
	const lf = "package p\n\nfunc other() {\n}\n\nfunc productionEnv() machineEnv {\n\treturn machineEnv{}\n}\n\nfunc after() {\n}\n"
	want := "func productionEnv() machineEnv {\n\treturn machineEnv{}"
	for _, tc := range []struct{ name, src string }{
		{"LF", lf},
		{"CRLF", strings.ReplaceAll(lf, "\n", "\r\n")},
	} {
		got, ok := funcBody(tc.src, "productionEnv")
		if !ok || got != want {
			t.Fatalf("%s: funcBody = %q, %v; want %q, true", tc.name, got, ok, want)
		}
	}
	for _, tc := range []struct{ name, src string }{
		{"missing symbol", "package p\n\nfunc other() {\n}\n"},
		{"empty source", ""},
		{"unterminated body", "package p\n\nfunc productionEnv() machineEnv {\n\treturn machineEnv{}"},
		{"prefix match only", "package p\n\nfunc productionEnvironment() {\n}\n"},
	} {
		if got, ok := funcBody(tc.src, "productionEnv"); ok {
			t.Fatalf("%s: funcBody = %q, true; want not found", tc.name, got)
		}
	}
}
