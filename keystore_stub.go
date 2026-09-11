//go:build !windows

package localtls

import "fmt"

func platformKeyStore() (MachineKeyStore, error) {
	return nil, fmt.Errorf("machine key store is not supported on this platform")
}

func platformKeyDeleter() (MachineKeyDeleter, error) {
	return nil, fmt.Errorf("machine key deleter is not supported on this platform")
}
