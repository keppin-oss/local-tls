//go:build windows

package localtls

import (
	"crypto"
	"fmt"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// servingCloseDiagDirEnv names the durable diagnostics directory of the live
// serving-close run. Without it the live test does not run.
const servingCloseDiagDirEnv = "KEPPIN_SERVING_CLOSE_DIAG_DIR"

// TestServingCloseRaceElevated is the live serving-close test: TLS handshakes
// concurrent with Material.Close on a real CNG test key. It creates exactly
// one key, Keppin.Test.ServingClose.<16 hex>, whose name is persisted in the
// diagnostics directory before Create, and deletes it once, by exact name,
// only when every handle's first Close returned nil and every scenario
// confirmed release. It never touches LocalMachine\Root and writes no TLS
// file. It is skipped (NOT EXECUTED), before any machine operation, without
// the diagnostics directory or without a privileged caller.
func TestServingCloseRaceElevated(t *testing.T) {
	dir := os.Getenv(servingCloseDiagDirEnv)
	if dir == "" {
		t.Skipf("the live serving-close test requires %s to name an existing diagnostics directory — NOT EXECUTED", servingCloseDiagDirEnv)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Skipf("%s=%q is not an existing directory (%v) — NOT EXECUTED", servingCloseDiagDirEnv, dir, err)
	}
	privileged, err := callerIsPrivileged()
	if err != nil || !privileged {
		t.Skipf("the live serving-close test requires an elevated Administrator or LocalSystem (privileged=%v, err=%v) — NOT EXECUTED", privileged, err)
	}
	t.Logf("principal: %s", servingClosePrincipal())

	ops := ccKeyOps{
		newName:   newServingCloseKeyName,
		writeDiag: func(name string) error { return writeServingCloseDiag(dir, name) },
		open:      TestOpenKey,
		create:    TestCreateKey,
		del:       TestDeleteKey,
	}
	run := func(created crypto.Signer, open func() (crypto.Signer, error)) ccRunOutcome {
		return runCCScenarios(ccLiveConfig, time.Now(), created, open)
	}
	rep := executeServingClose(ops, run, t.Logf)

	if rep.Run != nil {
		for _, s := range rep.Run.Scenarios {
			t.Logf("%s: %s", s.Obs.Scenario, s.Verdict)
			for _, l := range ccDiagnosticLines(s.Obs) {
				t.Log(l)
			}
			if s.Obs.Stack != "" {
				t.Logf("%s goroutine dump at watchdog:\n%s", s.Obs.Scenario, s.Obs.Stack)
			}
		}
		for _, h := range rep.Run.Handles {
			t.Logf("handle %s: first Close returned=%v err=%v", h.Label, h.Closed, h.CloseErr)
		}
		for _, n := range rep.Run.Notes {
			t.Logf("note: %s", n)
		}
	}
	t.Logf("key %s: create attempted=%v, delete attempted=%v, delete confirmed=%v, key may remain=%v",
		rep.KeyName, rep.CreateAttempted, rep.DeleteAttempted, rep.DeleteConfirmed, rep.KeyMayRemain)
	if !rep.Pass {
		t.Fatalf("live serving-close test not PASS: %s", rep.Stage)
	}
}

// servingClosePrincipal describes the process token: user SID, elevation and
// integrity level SID.
func servingClosePrincipal() string {
	tok := windows.GetCurrentProcessToken()
	sid := "unknown"
	if u, err := tok.GetTokenUser(); err == nil {
		sid = u.User.Sid.String()
	}
	integrity := "unknown"
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n > 0 {
		buf := make([]byte, n)
		if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err == nil {
			tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
			integrity = tml.Label.Sid.String()
		}
	}
	return fmt.Sprintf("user=%s elevated=%v integrity=%s", sid, tok.IsElevated(), integrity)
}
