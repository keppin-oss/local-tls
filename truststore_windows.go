//go:build windows

package localtls

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows CryptoAPI / certificate-store constants.
// These are not exported by golang.org/x/sys/windows at this version.
const (
	certStoreProvSystem         = 10
	certSystemStoreLocalMachine = 0x00020000

	certStoreAddNew             = 1 // CERT_STORE_ADD_NEW — fails if duplicate exists
	certStoreAddReplaceExisting = 3 // CERT_STORE_ADD_REPLACE_EXISTING

	certFindExisting = 0x0000000d // CERT_FIND_EXISTING

	x509AsnEncoding  = 0x00000001
	pkcs7AsnEncoding = 0x00010000

	certStoreReadOnlyFlag = 0x00008000 // CERT_STORE_READONLY_FLAG
)

// machineRootStoreName is the system store name for the machine Root store.
var machineRootStoreName = syscall.StringToUTF16("Root")

// platformTrustStore returns the Windows TrustStore backed by LocalMachine\Root.
func platformTrustStore() (TrustStore, error) {
	return &windowsTrustStore{}, nil
}

// windowsTrustStore implements TrustStore using Windows CryptoAPI
// targeting LocalMachine\Root.
type windowsTrustStore struct{}

// openMachineRootStore opens the LocalMachine\Root certificate store.
func openMachineRootStore() (windows.Handle, error) {
	store, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certSystemStoreLocalMachine,
		uintptr(unsafe.Pointer(&machineRootStoreName[0])),
	)
	if err != nil {
		return 0, fmt.Errorf("CertOpenStore(LocalMachine\\Root): %w", err)
	}
	return store, nil
}

// openMachineRootStoreReadOnly opens LocalMachine\Root for read-only access.
func openMachineRootStoreReadOnly() (windows.Handle, error) {
	store, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certSystemStoreLocalMachine|certStoreReadOnlyFlag,
		uintptr(unsafe.Pointer(&machineRootStoreName[0])),
	)
	if err != nil {
		return 0, fmt.Errorf("CertOpenStore(LocalMachine\\Root read-only): %w", err)
	}
	return store, nil
}

// InstallTrust installs the CA certificate DER into LocalMachine\Root.
func (s *windowsTrustStore) InstallTrust(certificateDER []byte) error {
	if len(certificateDER) == 0 {
		return fmt.Errorf("empty certificate DER")
	}

	store, err := openMachineRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	fp := sha256.Sum256(certificateDER)

	existing, err := findCertBySHA256(store, fp)
	if err != nil {
		return fmt.Errorf("find existing certificate: %w", err)
	}
	if existing != nil {
		windows.CertFreeCertificateContext(existing)
		return nil // idempotent: already installed
	}

	certCtx, err := windows.CertCreateCertificateContext(
		x509AsnEncoding|pkcs7AsnEncoding,
		&certificateDER[0],
		uint32(len(certificateDER)),
	)
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext: %w", err)
	}
	defer windows.CertFreeCertificateContext(certCtx)

	err = windows.CertAddCertificateContextToStore(
		store, certCtx, certStoreAddReplaceExisting, nil,
	)
	if err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore: %w", err)
	}
	return nil
}

// deleteCertificateFromStore deletes cert from the store and returns the result.
// CertDeleteCertificateFromStore takes ownership of cert and frees it (it calls
// CertFreeCertificateContext internally), so the caller must not free cert again.
func deleteCertificateFromStore(cert *windows.CertContext) error {
	return windows.CertDeleteCertificateFromStore(cert)
}

// RemoveTrust removes the exact CA certificate from LocalMachine\Root.
func (s *windowsTrustStore) RemoveTrust(certificateDER []byte) error {
	if len(certificateDER) == 0 {
		return fmt.Errorf("empty certificate DER")
	}

	store, err := openMachineRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	fp := sha256.Sum256(certificateDER)
	existing, err := findCertBySHA256(store, fp)
	if err != nil {
		return fmt.Errorf("find certificate to remove: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("%w", ErrTrustAnchorNotFound)
	}

	if err := deleteCertificateFromStore(existing); err != nil {
		return fmt.Errorf("CertDeleteCertificateFromStore: %w", err)
	}
	return nil
}

// RemoveTrustBySHA256 removes a certificate from LocalMachine\Root identified
// by its exact SHA-256 fingerprint. Unlike RemoveTrust, this does not require
// the DER bytes — it finds and deletes the certificate by fingerprint alone.
//
// This is useful for cleanup when the original DER file is no longer available
// (e.g. the state directory was already deleted).
func (s *windowsTrustStore) RemoveTrustBySHA256(fp [32]byte) error {
	store, err := openMachineRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	existing, err := findCertBySHA256(store, fp)
	if err != nil {
		return fmt.Errorf("find certificate by SHA-256: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("certificate with fingerprint %x not found in LocalMachine\\Root: %w", fp, ErrTrustAnchorNotFound)
	}

	if err := deleteCertificateFromStore(existing); err != nil {
		return fmt.Errorf("CertDeleteCertificateFromStore: %w", err)
	}
	return nil
}

// VerifyTrust checks whether the given CA certificate DER is trusted in
// LocalMachine\Root. Read-only, safe for non-elevated runtime.
func (s *windowsTrustStore) VerifyTrust(certificateDER []byte) (TrustState, error) {
	if len(certificateDER) == 0 {
		return TrustError, fmt.Errorf("empty certificate DER")
	}

	store, err := openMachineRootStoreReadOnly()
	if err != nil {
		return TrustError, fmt.Errorf("open Root store: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	cert, err := windows.CertCreateCertificateContext(
		x509AsnEncoding|pkcs7AsnEncoding,
		&certificateDER[0],
		uint32(len(certificateDER)),
	)
	if err != nil {
		return TrustError, fmt.Errorf("CertCreateCertificateContext: %w", err)
	}
	defer windows.CertFreeCertificateContext(cert)

	cn, _ := getCertCommonName(cert)
	fp := sha256.Sum256(certificateDER)

	existing, err := findCertBySHA256(store, fp)
	if err != nil {
		return TrustError, fmt.Errorf("find certificate by SHA-256: %w", err)
	}
	if existing != nil {
		windows.CertFreeCertificateContext(existing)
		return TrustHealthy, nil
	}

	if cn != "" {
		conflict, err := findCertByCN(store, cn)
		if err != nil {
			return TrustError, fmt.Errorf("find certificate by CN: %w", err)
		}
		if conflict != nil {
			windows.CertFreeCertificateContext(conflict)
			return TrustConflict, nil
		}
	}

	return TrustAbsent, nil
}

// IsTrustedSHA256 reports whether a certificate fingerprint is in the store.
func (s *windowsTrustStore) IsTrustedSHA256(fingerprint [32]byte) (bool, error) {
	store, err := openMachineRootStoreReadOnly()
	if err != nil {
		return false, fmt.Errorf("open Root store: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	existing, err := findCertBySHA256(store, fingerprint)
	if err != nil {
		return false, err
	}
	if existing != nil {
		windows.CertFreeCertificateContext(existing)
		return true, nil
	}
	return false, nil
}

// EnsureTrusted delegates to InstallTrust.
func (s *windowsTrustStore) EnsureTrusted(certificateDER []byte) error {
	return s.InstallTrust(certificateDER)
}

// findCertBySHA256 finds a certificate in the store by its SHA-256 fingerprint.
// Uses CertEnumCertificatesInStore + pure-Go SHA-256 to avoid CRYPT_HASH_BLOB
// struct-layout / alignment mismatches between Go and the Windows C ABI.
// Returns nil if not found. The caller must free the returned context.
//
// IMPORTANT: CertEnumCertificatesInStore frees pPrevCertContext internally
// (per MSDN). Do NOT call CertFreeCertificateContext on prev yourself.
func findCertBySHA256(store windows.Handle, fp [32]byte) (*windows.CertContext, error) {
	var prev *windows.CertContext
	for {
		cert, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if isEnumEnd(err) {
				return nil, nil
			}
			return nil, err
		}
		// prev has already been freed by CertEnumCertificatesInStore.
		if cert == nil {
			return nil, nil
		}

		// Compute SHA-256 of the stored certificate's encoded DER.
		certDER := unsafe.Slice(cert.EncodedCert, int(cert.Length))
		if sha256.Sum256(certDER) == fp {
			return cert, nil
		}
		prev = cert
	}
}

// isEnumEnd returns true when the error signals end-of-enumeration.
func isEnumEnd(err error) bool {
	if err == nil {
		return false
	}
	// CRYPT_E_NOT_FOUND = 0x80092004 signals end of enumeration.
	if e, ok := err.(syscall.Errno); ok {
		return uintptr(e)&0xFFFF == 0x2004 || e == 0x80092004
	}
	return bytes.Contains([]byte(err.Error()), []byte("0x80092004"))
}

// findCertByCN finds a certificate by subject Common Name.
//
// CERT_FIND_SUBJECT_STR_A performs a case-insensitive substring match against
// the subject's simple-name string and requires pvFindPara to point to a
// null-terminated ANSI (8-bit) string. The value is 0x00070007, not 0x00080007
// (that latter value is CERT_FIND_SUBJECT_STR_W, which expects a UTF-16 string).
func findCertByCN(store windows.Handle, cn string) (*windows.CertContext, error) {
	cnBytes := append([]byte(cn), 0)

	cert, err := windows.CertFindCertificateInStore(
		store,
		x509AsnEncoding|pkcs7AsnEncoding,
		0,
		windows.CERT_FIND_SUBJECT_STR_A,
		unsafe.Pointer(&cnBytes[0]),
		nil,
	)
	if err != nil {
		if isCertNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return cert, nil
}

// getCertCommonName extracts the Common Name from a CertContext subject.
func getCertCommonName(cert *windows.CertContext) (string, error) {
	const certNameSimpleDisplayType = 4
	const certNameStrNoPlusFlag = 0x20000000

	// First call to get required buffer size.
	size := windows.CertGetNameString(
		cert, certNameSimpleDisplayType, certNameStrNoPlusFlag, nil, nil, 0,
	)
	if size == 0 {
		return "", nil
	}

	buf := make([]uint16, size)
	windows.CertGetNameString(
		cert, certNameSimpleDisplayType, certNameStrNoPlusFlag, nil, &buf[0], size,
	)
	return syscall.UTF16ToString(buf), nil
}

// isCertNotFound returns true if err is CRYPT_E_NOT_FOUND.
func isCertNotFound(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(syscall.Errno); ok {
		return uintptr(e)&0xFFFF == 0x2004 || e == 0x80092004
	}
	return bytes.Contains([]byte(err.Error()), []byte("0x80092004")) ||
		bytes.Contains([]byte(err.Error()), []byte("Cannot find object or property"))
}
