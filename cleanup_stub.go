//go:build !windows

package localtls

import "fmt"

// CleanupMachine is not supported on non-Windows platforms.
func CleanupMachine() error {
	return fmt.Errorf("cleanup is not supported on this platform; Windows only")
}

// CleanupMachineBySHA256 is not supported on non-Windows platforms.
func CleanupMachineBySHA256(fp [32]byte) error {
	return fmt.Errorf("cleanup is not supported on this platform; Windows only")
}
