//go:build windows

package localtls

import (
	"errors"
	"fmt"
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
// roles delegate open/create/delete custody to the shared windowscng package
// through the policy-aware API, rather than retaining a second native
// implementation.
func TestKeyRolesDelegateCustodyToWindowscng(t *testing.T) {
	src, ok := localTLSImplFiles(t)["keystore_windows.go"]
	if !ok {
		t.Fatal("keystore_windows.go not found")
	}
	for _, call := range []string{
		"windowscng.LoadOrCreateWithPolicy",
		"windowscng.OpenWithPolicy",
		"windowscng.ApplyPolicy",
		"windowscng.Delete",
	} {
		if !strings.Contains(src, call) {
			t.Errorf("keystore_windows.go does not delegate to %s", call)
		}
	}
}

// legacyPolicyFreeCalls are the windowscng v0.1 functions that open or create
// a key with the single shared service-signer DACL and validate it without a
// per-key policy. Production key custody must not use them.
var legacyPolicyFreeCalls = []string{"windowscng.Open(", "windowscng.LoadOrCreate("}

// TestProductionCodeAvoidsLegacyPolicyFreeCNG proves that no production
// implementation file opens or creates a key through the legacy, policy-free
// windowscng functions. verify_windows.go is the only exception: its exported
// Test* helpers are restricted to the Keppin.Test.* namespace and never touch
// a production key name.
func TestProductionCodeAvoidsLegacyPolicyFreeCNG(t *testing.T) {
	for file, src := range localTLSImplFiles(t) {
		if file == "verify_windows.go" {
			continue
		}
		for _, call := range legacyPolicyFreeCalls {
			if strings.Contains(src, call) {
				t.Errorf("%s calls legacy policy-free %s; use the per-role policy API", file, call)
			}
		}
	}
	src := localTLSImplFiles(t)["verify_windows.go"]
	for _, name := range []string{"caKeyName", "serverKeyName", "ProdCAKeyName", "ProdServerKeyName"} {
		if strings.Contains(src, name) {
			t.Errorf("verify_windows.go (legacy test-namespace helpers) must not reference production key %s", name)
		}
	}
}

// TestKeyPolicyPerRole proves the policy assigned to each production key role
// and that an unknown name has no policy.
func TestKeyPolicyPerRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		want windowscng.Policy
	}{
		{caKeyName, windowscng.PolicyPrivilegedOnly},
		{serverKeyName, windowscng.PolicyServiceSigner},
	} {
		got, err := keyPolicy(tc.name)
		if err != nil || got != tc.want {
			t.Errorf("keyPolicy(%q) = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	for _, name := range []string{"", identity.TestKeyNamespace + "x", caKeyName + "x", strings.ToLower(caKeyName)} {
		if _, err := keyPolicy(name); err == nil {
			t.Errorf("keyPolicy(%q) returned a policy; want an error", name)
		}
	}
}

// recordingPolicyAPI is a cngPolicyAPI fake that records every call and never
// touches a machine key.
type recordingPolicyAPI struct {
	calls []string
	err   error
}

func (r *recordingPolicyAPI) api() cngPolicyAPI {
	signer := func(op, name string, p windowscng.Policy) (windowscng.Signer, error) {
		r.calls = append(r.calls, op+" "+name+" "+p.String())
		if r.err != nil {
			return nil, r.err
		}
		return newFakeCloseSigner(), nil
	}
	return cngPolicyAPI{
		open: func(name string, p windowscng.Policy) (windowscng.Signer, error) {
			return signer("open", name, p)
		},
		loadOrCreate: func(name string, p windowscng.Policy) (windowscng.Signer, error) {
			return signer("loadOrCreate", name, p)
		},
		apply: func(name string, p windowscng.Policy) error {
			r.calls = append(r.calls, "apply "+name+" "+p.String())
			return r.err
		},
	}
}

// TestProductionKeyOperationsUseRolePolicy proves that open, open-or-create and
// tighten pass exactly the role policy of each key to windowscng.
func TestProductionKeyOperationsUseRolePolicy(t *testing.T) {
	rec := &recordingPolicyAPI{}
	api := rec.api()
	for _, name := range []string{caKeyName, serverKeyName} {
		if _, err := openProductionKeyWith(api, name); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateKeyWith(api, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := tightenCAKeyPolicyWith(api); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"open " + caKeyName + " privileged-only",
		"loadOrCreate " + caKeyName + " privileged-only",
		"open " + serverKeyName + " service-signer",
		"loadOrCreate " + serverKeyName + " service-signer",
		"apply " + caKeyName + " privileged-only",
	}
	if strings.Join(rec.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(rec.calls, "\n"), strings.Join(want, "\n"))
	}
}

// TestProductionKeyOperationsRejectUnknownName proves no windowscng call is
// made for a name without a role policy.
func TestProductionKeyOperationsRejectUnknownName(t *testing.T) {
	rec := &recordingPolicyAPI{}
	api := rec.api()
	name := identity.TestKeyNamespace + "Unknown"
	if _, err := openProductionKeyWith(api, name); err == nil {
		t.Error("open of an unknown name succeeded")
	}
	if _, err := loadOrCreateKeyWith(api, name); err == nil {
		t.Error("open-or-create of an unknown name succeeded")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("windowscng called for an unknown name: %v", rec.calls)
	}
}

// TestProductionKeyOperationsMapPolicyErrors proves that the policy-aware
// windowscng failures reach callers as Local-TLS sentinels.
func TestProductionKeyOperationsMapPolicyErrors(t *testing.T) {
	for _, tc := range []struct {
		cngErr error
		want   error
	}{
		{fmt.Errorf("key %q: NCryptOpenKey hr=0x80090016: %w", caKeyName, windowscng.ErrKeyNotFound), ErrKeyNotFound},
		{fmt.Errorf("key %q (privileged-only): %w: persisted DACL is service-signer", caKeyName, windowscng.ErrPolicyMismatch), ErrKeyPolicyMismatch},
		{windowscng.ErrPrivilegeRequired, ErrPrivilegeRequired},
	} {
		rec := &recordingPolicyAPI{err: tc.cngErr}
		api := rec.api()
		if _, err := openProductionKeyWith(api, caKeyName); !errors.Is(err, tc.want) {
			t.Errorf("open: %v, want %v", err, tc.want)
		}
		if _, err := loadOrCreateKeyWith(api, caKeyName); !errors.Is(err, tc.want) {
			t.Errorf("loadOrCreate: %v, want %v", err, tc.want)
		}
		if err := tightenCAKeyPolicyWith(api); !errors.Is(err, tc.want) {
			t.Errorf("apply: %v, want %v", err, tc.want)
		}
	}
}

// TestMapCNGErrorPolicySentinels proves the policy and privilege sentinels are
// mapped, keep the shared chain (for example ErrCleanupFailed) and are never
// turned into ErrKeyNotFound.
func TestMapCNGErrorPolicySentinels(t *testing.T) {
	cleanup := errors.Join(fmt.Errorf("created key failed verification: %w", windowscng.ErrPolicyMismatch), windowscng.ErrCleanupFailed)
	err := mapCNGError(cleanup)
	if !errors.Is(err, ErrKeyPolicyMismatch) || !errors.Is(err, windowscng.ErrCleanupFailed) {
		t.Fatalf("mapped %v must match ErrKeyPolicyMismatch and keep ErrCleanupFailed", err)
	}
	if errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrPrivilegeRequired) {
		t.Fatalf("policy mismatch mapped to another sentinel: %v", err)
	}
	err = mapCNGError(windowscng.ErrPrivilegeRequired)
	if !errors.Is(err, ErrPrivilegeRequired) || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("privilege error mapped to %v", err)
	}
	if mapCNGError(nil) != nil {
		t.Fatal("mapCNGError(nil) must be nil")
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

// TestMapCNGErrorKeepsNativeHRESULT verifies the mapped error keeps the key
// name and native HRESULT that windowscng v0.2.0 puts in its wrapping error,
// while remaining matchable as ErrKeyNotFound and not leaking the sentinel.
func TestMapCNGErrorKeepsNativeHRESULT(t *testing.T) {
	underlying := fmt.Errorf("key %q: NCryptOpenKey hr=0x%x: %w", serverKeyName, uint32(0x80090016), windowscng.ErrKeyNotFound)
	err := mapCNGError(underlying)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mapped error must match ErrKeyNotFound: %v", err)
	}
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatal("mapped error must not leak the windowscng sentinel")
	}
	for _, want := range []string{"hr=0x80090016", serverKeyName} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("mapped error %q lost %q", err, want)
		}
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
