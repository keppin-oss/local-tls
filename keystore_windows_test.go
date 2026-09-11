//go:build windows

package localtls

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/local-tls/internal/identity"
)

// localTLSImplFiles returns the non-test .go files in the Local-TLS package
// root. Implementation files must not duplicate the native CNG layer that now
// lives in CNG/windowscng.
func localTLSImplFiles(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		out[file] = string(data)
	}
	if len(out) == 0 {
		t.Fatal("no Local-TLS implementation files found")
	}
	return out
}

// forbiddenNativeCNG are tokens that must not appear in the Local-TLS
// implementation: the native CNG/KSP/ACL implementation has been migrated to
// CNG/windowscng and must not be duplicated here.
var forbiddenNativeCNG = []string{
	"ncrypt.dll",
	"NCryptOpenStorageProvider",
	"NCryptCreatePersistedKey",
	"NCryptSetProperty",
	"NCryptGetProperty",
	"NCryptFinalizeKey",
	"NCryptExportKey",
	"NCryptSignHash",
	"NCryptDeleteKey",
	"NCryptFreeObject",
	"NCryptOpenKey",
	"advapi32",
	"ConvertStringSecurityDescriptorToSecurityDescriptor",
	"GetSecurityDescriptorDacl",
	"GetAclInformation",
	"GetAce",
	"EqualSid",
	"ConvertStringSidToSid",
	"ConvertSidToStringSid",
	"ECCPUBLICBLOB",
	"ECDSA_P256",
	"keySecuritySDDL",
}

// TestNoDuplicatedNativeCNGImplementation proves no native NCrypt implementation
// remains in the Local-TLS package. All native CNG/KSP custody now lives in
// CNG/windowscng.
func TestNoDuplicatedNativeCNGImplementation(t *testing.T) {
	for file, src := range localTLSImplFiles(t) {
		for _, tok := range forbiddenNativeCNG {
			if strings.Contains(src, tok) {
				t.Errorf("Local-TLS implementation file %s contains duplicated native CNG token %q", file, tok)
			}
		}
	}
}

// TestUsesSharedWindowscngPackage proves the Local-TLS key custody depends on
// the shared CNG/windowscng package.
func TestUsesSharedWindowscngPackage(t *testing.T) {
	found := false
	for _, src := range localTLSImplFiles(t) {
		if strings.Contains(src, "keppin-oss/cng/windowscng") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Local-TLS implementation does not import github.com/keppin-oss/cng/windowscng")
	}
}

// TestKeyRolesDelegateCustodyToWindowscng proves both the CA and server key
// roles delegate open/create/delete custody to the shared windowscng package,
// rather than retaining a second native implementation.
func TestKeyRolesDelegateCustodyToWindowscng(t *testing.T) {
	src, ok := localTLSImplFiles(t)["keystore_windows.go"]
	if !ok {
		t.Fatal("keystore_windows.go not found")
	}
	for _, call := range []string{
		"windowscng.LoadOrCreate",
		"windowscng.Open",
		"windowscng.Delete",
	} {
		if !strings.Contains(src, call) {
			t.Errorf("keystore_windows.go does not delegate to %s", call)
		}
	}
}

// TestNoMachineIdentityOrEnterpriseTLSIdentity proves no Machine Identity or
// Enterprise-TLS key identity/policy leaks into Local-TLS.
func TestNoMachineIdentityOrEnterpriseTLSIdentity(t *testing.T) {
	forbidden := []string{
		"Keppin.Agent.MachineIdentity",
		"Keppin.Agent.EnterpriseTLS",
		"keppin-enterprise-tls",
		"MachineIdentity",
		"EnterpriseTLS",
	}
	for file, src := range localTLSImplFiles(t) {
		for _, tok := range forbidden {
			if strings.Contains(src, tok) {
				t.Errorf("Local-TLS implementation file %s references forbidden identity/policy %q", file, tok)
			}
		}
	}
}

// TestMapCNGErrorNotFound verifies the shared missing-key sentinel is mapped to
// the Local-TLS ErrKeyNotFound contract so callers never need to know
// windowscng's sentinel.
func TestMapCNGErrorNotFound(t *testing.T) {
	err := mapCNGError(windowscng.ErrKeyNotFound)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mapCNGError(windowscng.ErrKeyNotFound) = %v, want ErrKeyNotFound", err)
	}
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatal("mapped error must not leak the windowscng sentinel")
	}
}

// TestMapCNGErrorNotFoundWrapped verifies a wrapped shared missing-key error is
// still mapped (the shared package wraps with key-name context).
func TestMapCNGErrorNotFoundWrapped(t *testing.T) {
	underlying := wrapCNGErr(windowscng.ErrKeyNotFound)
	if !errors.Is(underlying, windowscng.ErrKeyNotFound) {
		t.Fatalf("precondition: wrapCNGErr result must retain windowscng.ErrKeyNotFound")
	}
	if !errors.Is(mapCNGError(underlying), ErrKeyNotFound) {
		t.Fatalf("mapCNGError(wrapped) must map to ErrKeyNotFound")
	}
}

// TestMapCNGErrorPassThrough verifies non-not-found failures are never converted
// into not-found.
func TestMapCNGErrorPassThrough(t *testing.T) {
	sentinel := errors.New("localtls: permission denied")
	err := mapCNGError(sentinel)
	if err != sentinel {
		t.Fatalf("mapCNGError(pass-through) = %v, want original error", err)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatal("a permission error must not be converted into ErrKeyNotFound")
	}
}

func wrapCNGErr(err error) error {
	return &wrappedCNGError{inner: err}
}

type wrappedCNGError struct{ inner error }

func (w *wrappedCNGError) Error() string { return w.inner.Error() }
func (w *wrappedCNGError) Unwrap() error { return w.inner }

// TestProductionKeyNamesUnchanged proves the Local CA and server production key
// names remain owned by Local-TLS and unchanged.
func TestProductionKeyNamesUnchanged(t *testing.T) {
	if caKeyName != identity.ProdCAKeyName {
		t.Fatalf("caKeyName = %q, want %q", caKeyName, identity.ProdCAKeyName)
	}
	if serverKeyName != identity.ProdServerKeyName {
		t.Fatalf("serverKeyName = %q, want %q", serverKeyName, identity.ProdServerKeyName)
	}
	for _, name := range []string{caKeyName, serverKeyName} {
		if strings.HasPrefix(name, identity.TestKeyNamespace) {
			t.Errorf("production key %q must not live in the test namespace %q", name, identity.TestKeyNamespace)
		}
		if strings.HasPrefix(name, identity.SmokeKeyNamespace) {
			t.Errorf("production key %q must not live in the smoke namespace %q", name, identity.SmokeKeyNamespace)
		}
	}
}
