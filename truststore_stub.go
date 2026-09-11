//go:build !windows

package localtls

import "fmt"

func platformTrustStore() (TrustStore, error) {
	return nil, fmt.Errorf("machine trust store is not supported on this platform")
}
