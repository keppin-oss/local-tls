//go:build windows

package main

import (
	"errors"
	"fmt"
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
