//go:build windows

// Command verify performs manual verification for the Local TLS module.
// It creates, opens, tests signing, and deletes test keys under the
// Keppin.Test.* namespace, and exercises the machine trust-store adapter.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/keppin-oss/local-tls"
	"github.com/keppin-oss/local-tls/internal/identity"
)

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 2 {
		printUsage()
		return 2
	}

	switch os.Args[1] {
	case "-create":
		return handleCreate()
	case "-open":
		return handleOpen()
	case "-sign":
		return handleSign()
	case "-delete":
		return handleDelete()
	case "-trust-install":
		return handleTrustInstall()
	case "-trust-verify":
		return handleTrustVerify()
	case "-trust-remove":
		return handleTrustRemove()
	case "-trust-is":
		return handleTrustIsSHA256()
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown operation %q\n", os.Args[1])
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: verify <operation>

CNG operations:
  -create   Create test key (requires elevated Administrator)
  -open     Open test key as current principal (expected DENIED for ordinary users)
  -sign     Sign and verify a test message (run as NT AUTHORITY\LocalService)
  -delete   Delete the exact test key (requires elevated Administrator)

Trust store operations:
  -trust-install <pemfile>   Install CA cert into LocalMachine\Root (requires elevation)
  -trust-verify  <pemfile>   Verify CA cert is trusted in LocalMachine\Root (non-elevated)
  -trust-remove  <pemfile>   Remove CA cert from LocalMachine\Root (requires elevation)
  -trust-is      <sha256hex> Check if fingerprint is trusted (non-elevated)

Environment:
  `+identity.EnvPrefix+`_VERIFY_KEY_NAME   Exact `+identity.TestKeyNamespace+`* key name for open/sign/delete.
`)
}

func keyName() string {
	if name := os.Getenv(identity.EnvPrefix + "_VERIFY_KEY_NAME"); name != "" {
		if !strings.HasPrefix(name, identity.TestKeyNamespace) {
			fmt.Fprintf(os.Stderr, "ERROR: "+identity.EnvPrefix+"_VERIFY_KEY_NAME must start with %q\n", identity.TestKeyNamespace)
			os.Exit(2)
		}
		return name
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot generate random key suffix: %v\n", err)
		os.Exit(1)
	}
	return fmt.Sprintf(identity.TestKeyNamespace+"LocalHTTPS.verify.%s", hex.EncodeToString(buf[:]))
}

type closer interface{ Close() error }

func closeSigner(s crypto.Signer) {
	if c, ok := s.(closer); ok {
		_ = c.Close()
	}
}

func handleCreate() int {
	name := keyName()
	fmt.Printf("CREATE %s\n", name)
	signer, err := localtls.TestCreateKey(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: create failed: %v\n", err)
		return 1
	}
	defer closeSigner(signer)
	fmt.Printf("OK key=%s pub=%T\n", name, signer.Public())
	fmt.Printf("EXPORT "+identity.EnvPrefix+"_VERIFY_KEY_NAME=%s\n", name)
	return 0
}

func handleOpen() int {
	name := keyName()
	fmt.Printf("OPEN %s\n", name)
	signer, err := localtls.TestOpenKey(name)
	if err != nil {
		msg := err.Error()
		if isAccessDenied(msg) {
			fmt.Printf("DENIED (expected for ordinary user): %v\n", err)
			fmt.Println("ACCESS_CHECK ordinary-user deny test PASSED")
			return 0
		}
		fmt.Fprintf(os.Stderr, "ERROR: open failed (not access-denied): %v\n", err)
		return 1
	}
	defer closeSigner(signer)
	fmt.Printf("OK key=%s pub=%T\n", name, signer.Public())
	fmt.Println("WARNING: open succeeded — caller has more access than expected for ordinary user")
	return 1
}

func handleSign() int {
	name := keyName()
	fmt.Printf("SIGN %s\n", name)
	signer, err := localtls.TestOpenKey(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: open for sign: %v\n", err)
		return 1
	}
	defer closeSigner(signer)
	if err := localtls.TestSignAndVerify(signer); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: sign+verify: %v\n", err)
		return 1
	}
	fmt.Println("OK sign+verify signature cryptographically valid")
	return 0
}

func handleDelete() int {
	name := keyName()
	fmt.Printf("DELETE %s\n", name)
	if err := localtls.TestDeleteKey(name); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: delete failed: %v\n", err)
		return 1
	}
	fmt.Printf("OK deleted %s\n", name)
	return 0
}

func isAccessDenied(msg string) bool {
	lower := strings.ToLower(msg)
	for _, ind := range []string{
		"access is denied",
		"access denied",
		"0x80090010", // NTE_PERM
		"0x801f0005", // STATUS_ACCESS_DENIED
	} {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// --- Trust store operations ---

func handleTrustInstall() int {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "ERROR: -trust-install requires a PEM file argument\n")
		return 2
	}
	der, err := readPEMFile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading certificate: %v\n", err)
		return 1
	}

	store, err := localtls.PlatformTrustStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: PlatformTrustStore: %v\n", err)
		return 1
	}

	fp := localtls.ComputeSHA256Fingerprint(der)
	fmt.Printf("INSTALL %x\n", fp)

	if err := store.InstallTrust(der); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: InstallTrust: %v\n", err)
		return 1
	}
	fmt.Printf("OK installed fingerprint %x\n", fp)
	return 0
}

func handleTrustVerify() int {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "ERROR: -trust-verify requires a PEM file argument\n")
		return 2
	}
	der, err := readPEMFile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading certificate: %v\n", err)
		return 1
	}

	store, err := localtls.PlatformTrustStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: PlatformTrustStore: %v\n", err)
		return 1
	}

	fp := localtls.ComputeSHA256Fingerprint(der)
	fmt.Printf("VERIFY %x\n", fp)

	state, verr := store.VerifyTrust(der)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "ERROR: VerifyTrust: %v\n", verr)
		return 1
	}
	fmt.Printf("TRUST %s\n", state)
	if state == localtls.TrustHealthy {
		return 0
	}
	fmt.Fprintf(os.Stderr, "WARNING: trust is not healthy — state=%s\n", state)
	return 1
}

func handleTrustRemove() int {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "ERROR: -trust-remove requires a PEM file argument\n")
		return 2
	}
	der, err := readPEMFile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading certificate: %v\n", err)
		return 1
	}

	store, err := localtls.PlatformTrustStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: PlatformTrustStore: %v\n", err)
		return 1
	}

	fp := localtls.ComputeSHA256Fingerprint(der)
	fmt.Printf("REMOVE %x\n", fp)

	if err := store.RemoveTrust(der); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: RemoveTrust: %v\n", err)
		return 1
	}
	fmt.Printf("OK removed fingerprint %x\n", fp)
	return 0
}

func handleTrustIsSHA256() int {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "ERROR: -trust-is requires a SHA-256 hex fingerprint argument\n")
		return 2
	}
	hexStr := strings.TrimSpace(os.Args[2])
	if len(hexStr) != 64 {
		fmt.Fprintf(os.Stderr, "ERROR: fingerprint must be 64 hex characters (32 bytes SHA-256)\n")
		return 2
	}
	fpBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid hex fingerprint: %v\n", err)
		return 2
	}
	var fp [32]byte
	copy(fp[:], fpBytes)

	store, err := localtls.PlatformTrustStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: PlatformTrustStore: %v\n", err)
		return 1
	}

	fmt.Printf("IS_TRUSTED %x\n", fp)
	found, err := store.IsTrustedSHA256(fp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: IsTrustedSHA256: %v\n", err)
		return 1
	}
	if found {
		fmt.Println("OK present")
		return 0
	}
	fmt.Println("ABSENT")
	return 1
}

// readPEMFile reads a PEM-encoded certificate file and returns DER bytes.
func readPEMFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type %q, expected CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.Raw, nil
}
