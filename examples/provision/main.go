//go:build windows

// Command provision demonstrates the elevated first-install/repair flow using
// ProvisionMachine.
//
// WARNING — this mutates machine state:
//   - creates or opens machine-scoped persisted CNG keys (CA + server);
//   - persists public CA/server certificate DER under %ProgramData%\Keppin\Agent\tls;
//   - installs the Local CA into LocalMachine\Root.
//
// It MUST be run from an Administrator-elevated process, MUST NOT be executed
// automatically in normal tests, and MUST only be runtime-validated on a
// disposable/appropriate Windows environment.
//
// NOT EXECUTED in ordinary validation. To validate manually:
//  1. Open an elevated PowerShell/Command Prompt.
//  2. go run ./examples/provision
//  3. Confirm the printed CA fingerprint and that the server cert is signed by
//     the Local CA with SANs localhost / 127.0.0.1 / ::1.
//  4. If cleanup is required, use CleanupMachine() (elevated) on a disposable
//     environment only.
package main

import (
	"fmt"
	"log"

	"github.com/keppin-oss/local-tls"
)

func main() {
	// Elevated provisioning / repair. Never called in normal per-process
	// startup; this is installer/repair behavior.
	material, err := localtls.ProvisionMachine()
	if err != nil {
		// Fails closed on inconsistent state rather than silently
		// regenerating a new CA/trust anchor.
		log.Fatalf("ProvisionMachine failed closed: %v", err)
	}

	fmt.Printf("provisioned local HTTPS material\n")
	fmt.Printf("CA fingerprint (SHA-256): %x\n", material.CAFingerprintSHA256)
	fmt.Printf("CA subject: %s\n", material.CACertificate.Subject)
	fmt.Printf("CA is self-signed CA: %t (pathlen-zero: %t)\n", material.CACertificate.IsCA, material.CACertificate.MaxPathLenZero)
	fmt.Printf("server subject: %s\n", material.ServerCertificate.Subject)
	fmt.Printf("server not after: %s\n", material.ServerCertificate.NotAfter)
	fmt.Printf("server DNS SANs: %v\n", material.ServerCertificate.DNSNames)
	fmt.Printf("server IP SANs: %v\n", material.ServerCertificate.IPAddresses)
	fmt.Printf("server issued by Local CA: %v\n", material.ServerCertificate.CheckSignatureFrom(material.CACertificate) == nil)
}
