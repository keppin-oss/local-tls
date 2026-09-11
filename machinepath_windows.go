//go:build windows

package localtls

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keppin-oss/local-tls/internal/identity"
)

// MachineAgentPath returns the production machine state root.
// On Windows this resolves %ProgramData%\Keppin\Agent\.
//
// This directory is machine-scoped (not per-user) and is the authoritative
// location for the machine Agent Service state, local TLS material, and
// installation-level configuration. Per-user credentials or session state
// MUST NOT be stored here.
//
// ACL intent (not enforced by Go):
//   - SYSTEM: Full Control
//   - Administrators: Full Control
//   - LOCAL SERVICE: only required access
//   - Ordinary interactive users: no direct access to machine-private state
func MachineAgentPath() (string, error) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		return "", fmt.Errorf("%%ProgramData%% is not set")
	}
	return filepath.Join(pd, identity.FileSystemDir, "Agent"), nil
}

// MachineTLSPath returns the production local TLS material directory.
// This is MachineAgentPath() + "\tls\".
//
// Only public certificate DER files are persisted here. No private-key
// files exist — private keys live in the machine-scoped CNG key store.
func MachineTLSPath() (string, error) {
	root, err := MachineAgentPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "tls"), nil
}
