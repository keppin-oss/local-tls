// Command fingerprint demonstrates the non-destructive fingerprint / cleanup
// handoff utilities of Local TLS.
//
// It shows:
//   - ParseSHA256Fingerprint — turn a 64-char hex fingerprint into a [32]byte;
//   - ComputeSHA256Fingerprint — derive the exact SHA-256 identity of a DER
//     certificate;
//   - the CleanupMachine vs CleanupMachineBySHA256 handoff decision.
//
// This example is intentionally non-destructive: it NEVER calls
// CleanupMachine or CleanupMachineBySHA256, and it never mutates machine trust
// or key state. It is cross-platform because the fingerprint utilities are
// platform-independent.
//
// Run:
//
//	go run ./examples/fingerprint
package main

import (
	"fmt"
	"log"

	"github.com/keppin-oss/local-tls"
)

func main() {
	// A real workflow obtains this from Material.CAFingerprintSHA256 (via
	// ProvisionMachine/LoadServingMaterial) or from a stored diagnostic value.
	// ParseSHA256Fingerprint tolerates surrounding whitespace and case.
	hexFP := "  a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899a0b1c2d3e4f5  "
	fp, err := localtls.ParseSHA256Fingerprint(hexFP)
	if err != nil {
		log.Fatalf("ParseSHA256Fingerprint failed: %v", err)
	}
	fmt.Printf("parsed fingerprint: %x\n", fp)

	// ComputeSHA256Fingerprint derives the same identity from raw DER bytes.
	// This placeholder is illustrative only; pass real certificate DER in
	// production.
	illustrativeDER := []byte("not-a-real-certificate-DER")
	computed := localtls.ComputeSHA256Fingerprint(illustrativeDER)
	fmt.Printf("computed fingerprint of illustrative bytes: %x\n", computed)

	fmt.Println()
	fmt.Println("Cleanup handoff decision (documented only — NOT executed here):")
	fmt.Println("  if the Local CA DER / TLS state directory is still present ->")
	fmt.Println("      use CleanupMachine()      (elevated; identifies the anchor from on-disk DER)")
	fmt.Println("  if the DER / state directory is already gone and you know the")
	fmt.Println("  exact fingerprint                                      ->")
	fmt.Println("      use CleanupMachineBySHA256(fp) (elevated; exact-fingerprint removal)")
	fmt.Println()
	fmt.Println("Both are Administrator-elevated, destructive, exact cleanup operations.")
	fmt.Println("They never delete by subject/CN, wildcard, prefix, or parent directory.")
}
