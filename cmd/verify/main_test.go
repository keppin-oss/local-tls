//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/keppin-oss/local-tls"
)

// TestClassifyOpen is offline: it classifies synthetic errors and never
// touches the KSP, the trust store or any ACL. It checks the label and the
// exact exit code that handleOpen returns, against literal expected values.
func TestClassifyOpen(t *testing.T) {
	badKeyset := "key \"Keppin.Test.x\": NCryptOpenKey hr=0x80090016"
	for _, tc := range []struct {
		name      string
		err       error
		wantLabel string
		wantExit  int
	}{
		{"opened", nil, "OPENED", 0},
		{"sentinel is not openable", fmt.Errorf("%w: %s", localtls.ErrKeyNotFound, badKeyset), "NOT_OPENABLE", 3},
		{"wrapped sentinel is not openable", fmt.Errorf("open: %w", fmt.Errorf("%w: %s", localtls.ErrKeyNotFound, badKeyset)), "NOT_OPENABLE", 3},
		{"bad keyset text without sentinel is an error", errors.New(badKeyset), "ERROR", 1},
		{"NTE_PERM text is an error", errors.New("NCryptOpenKey \"Keppin.Test.x\": hr=0x80090010"), "ERROR", 1},
		{"STATUS_ACCESS_DENIED text is an error", errors.New("status 0x801F0005"), "ERROR", 1},
		{"access denied text is an error", errors.New("Access is denied."), "ERROR", 1},
		{"failure without HRESULT is an error", errors.New("existing key Keppin.Test.x failed security validation"), "ERROR", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyOpen(tc.err)
			if got.label != tc.wantLabel || got.exit != tc.wantExit {
				t.Fatalf("classifyOpen(%v) = %s/%d, want %s/%d", tc.err, got.label, got.exit, tc.wantLabel, tc.wantExit)
			}
		})
	}
}

// TestParseSPKIArgs covers the -delete arguments offline: exactly one of
// -spki and -spki-file, a non-empty base64 value, and no fallback.
func TestParseSPKIArgs(t *testing.T) {
	want := []byte{0x30, 0x59, 0x30, 0x13}
	b64 := base64.StdEncoding.EncodeToString(want)
	files := map[string][]byte{"spki.txt": []byte("  " + b64 + "\r\n"), "empty.txt": []byte("\n")}
	readFile := func(path string) ([]byte, error) {
		if data, ok := files[path]; ok {
			return data, nil
		}
		return nil, os.ErrNotExist
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"value", []string{"-spki", b64}},
		{"file", []string{"-spki-file", "spki.txt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSPKIArgs(tc.args, readFile)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("parseSPKIArgs(%q) = %x, %v; want %x", tc.args, got, err, want)
			}
		})
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no flag", nil},
		{"flag without value", []string{"-spki"}},
		{"both flags", []string{"-spki", b64, "-spki-file", "spki.txt"}},
		{"unknown flag", []string{"-key", b64}},
		{"empty value", []string{"-spki", "  "}},
		{"empty file", []string{"-spki-file", "empty.txt"}},
		{"missing file", []string{"-spki-file", "missing.txt"}},
		{"not base64", []string{"-spki", "not*base64"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseSPKIArgs(tc.args, readFile); err == nil {
				t.Fatalf("parseSPKIArgs(%q) = %x, want an error", tc.args, got)
			}
		})
	}
}
