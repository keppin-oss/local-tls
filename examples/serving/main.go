//go:build windows

// Command serving demonstrates the preferred production HTTPS serving startup
// flow using LoadServingMaterial.
//
// Flow:
//
//	LoadServingMaterial()
//	        ↓
//	check error / fail closed
//	        ↓
//	use Material.Certificate in tls.Config
//
// LoadServingMaterial opens only the server CNG key (never the CA key), does
// not renew certificates, and never mutates LocalMachine\Root. It is the
// function the HTTPS listener MUST use for ordinary serving startup.
//
// Preconditions:
//   - machine provisioning must already have occurred (see examples/provision);
//   - the process must already have access to the persisted server key
//     (e.g. run as the machine Agent Service / LOCAL SERVICE principal).
//
// This example binds loopback only and serves no requests; it proves startup
// only. It does not use InsecureSkipVerify, does not access the CA key, and
// does not mutate trust state.
//
// Run from a process that has access to the persisted server key (no elevation
// required for the serving path itself):
//
//	go run ./examples/serving
package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/keppin-oss/local-tls"
)

func main() {
	// Preferred production serving entry point.
	material, err := localtls.LoadServingMaterial()
	if err != nil {
		// Fail closed: do not serve with missing/invalid/absent material.
		log.Fatalf("LoadServingMaterial failed closed: %v", err)
	}
	// Release the process-local CNG handle backing the serving signer before
	// process exit. This never deletes the persisted CNG key.
	defer material.Close()

	// Material.Certificate is the server TLS serving material. Its private
	// signing operation remains CNG-backed through crypto.Signer.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{material.Certificate},
		MinVersion:   tls.VersionTLS12,
	}

	// Loopback only — never bind a non-loopback address for this example.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		log.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	fmt.Printf("local HTTPS serving material loaded\n")
	fmt.Printf("CA fingerprint (SHA-256): %x\n", material.CAFingerprintSHA256)
	fmt.Printf("server subject: %s\n", material.ServerCertificate.Subject)
	fmt.Printf("server DNS SANs: %v\n", material.ServerCertificate.DNSNames)
	fmt.Printf("server IP SANs: %v\n", material.ServerCertificate.IPAddresses)
	fmt.Printf("loopback listener ready on %s (no requests served; startup proof only)\n", ln.Addr())
}
