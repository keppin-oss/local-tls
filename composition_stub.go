//go:build !windows

package localtls

import "fmt"

// MachineAgentPath returns an error on non-Windows platforms because
// machine-scoped state at %ProgramData% is a Windows-only concept.
func MachineAgentPath() (string, error) {
	return "", fmt.Errorf("machine agent path is not supported on this platform; Windows only")
}

// MachineTLSPath returns an error on non-Windows platforms.
func MachineTLSPath() (string, error) {
	return "", fmt.Errorf("machine TLS path is not supported on this platform; Windows only")
}

// ProvisionMachine is not supported on non-Windows platforms.
func ProvisionMachine() (Material, error) {
	return Material{}, fmt.Errorf("provision is not supported on this platform; Windows only")
}

// ReloadMachine is not supported on non-Windows platforms.
func ReloadMachine() (Material, error) {
	return Material{}, fmt.Errorf("reload is not supported on this platform; Windows only")
}

// LoadServingMaterial is not supported on non-Windows platforms.
func LoadServingMaterial() (Material, error) {
	return Material{}, fmt.Errorf("serving material is not supported on this platform; Windows only")
}

// StageServerRenewal is not supported on non-Windows platforms.
func StageServerRenewal() (CandidateRef, error) {
	return CandidateRef{}, fmt.Errorf("server renewal is not supported on this platform; Windows only")
}

// LoadServingCandidate is not supported on non-Windows platforms.
func LoadServingCandidate(ref CandidateRef) (Material, error) {
	return Material{}, fmt.Errorf("serving candidate is not supported on this platform; Windows only")
}

// ConfirmServingCandidate is not supported on non-Windows platforms.
func ConfirmServingCandidate(ref CandidateRef) error {
	return fmt.Errorf("serving candidate confirmation is not supported on this platform; Windows only")
}

// AbandonServingCandidate is not supported on non-Windows platforms.
func AbandonServingCandidate(ref CandidateRef) error {
	return fmt.Errorf("serving candidate abandon is not supported on this platform; Windows only")
}
