//go:build windows

package localtls

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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

// implSelectors returns, for one implementation file, every selector used on
// the windowscng package (windowscng.Open → "Open") and every identifier
// declared or referenced in it. It parses the code, so comments and the tests
// that list forbidden names do not count.
func implSelectors(t *testing.T, file, src string) (cng map[string]bool, idents map[string]bool, literals []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	cng, idents = map[string]bool{}, map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "windowscng" {
				cng[x.Sel.Name] = true
			}
		case *ast.Ident:
			idents[x.Name] = true
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				literals = append(literals, x.Value)
			}
		}
		return true
	})
	return cng, idents, literals
}

// TestKeyRolesDelegateCustodyToWindowscng proves both the CA and server key
// roles delegate open, create and delete custody to the cng v0.5 primitives,
// rather than retaining a second native implementation.
func TestKeyRolesDelegateCustodyToWindowscng(t *testing.T) {
	src, ok := localTLSImplFiles(t)["keystore_windows.go"]
	if !ok {
		t.Fatal("keystore_windows.go not found")
	}
	cng, _, _ := implSelectors(t, "keystore_windows.go", src)
	for _, fn := range []string{"Open", "Create", "Delete"} {
		if !cng[fn] {
			t.Errorf("keystore_windows.go does not delegate to windowscng.%s", fn)
		}
	}
}

// moduleImplFiles returns every non-test .go file of the module, keyed by its
// slash-separated path from the module root, whatever its build tags: the
// package root, cmd/, internal/ and examples/. Hidden directories, testdata,
// vendor and the generated graphify-out are skipped.
func moduleImplFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "graphify-out") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(path)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"keystore_windows.go", "cmd/verify/main.go", "internal/identity/identity.go"} {
		if _, ok := out[want]; !ok {
			t.Fatalf("module scan missed %s", want)
		}
	}
	return out
}

// removedCNGFunctions are the windowscng functions removed in cng v0.5.0,
// together with Apply, which Local-TLS no longer uses: no key DACL is ever
// rewritten.
var removedCNGFunctions = []string{
	"LoadOrCreate", "LoadOrCreateWithPolicy", "OpenWithPolicy", "ApplyPolicy",
	"OpenForService", "LoadOrCreateForService", "CreateForService",
	"DeleteForService", "ApplyServicePolicy", "Apply",
}

// TestNoRemovedKeyLifecycleInCode proves, on the parsed implementation code of
// every package of the module, that no file calls a removed or unused
// windowscng function, that no open-or-create helper survives under any name,
// and that no certreq path exists. The check reads code, not text, so this
// test may name them.
func TestNoRemovedKeyLifecycleInCode(t *testing.T) {
	for file, src := range moduleImplFiles(t) {
		cng, idents, literals := implSelectors(t, file, src)
		for _, fn := range removedCNGFunctions {
			if cng[fn] {
				t.Errorf("%s calls windowscng.%s", file, fn)
			}
		}
		for id := range idents {
			if strings.Contains(strings.ToLower(id), "loadorcreate") {
				t.Errorf("%s declares or references %s: opening and creating a key are separate operations", file, id)
			}
			if strings.Contains(strings.ToLower(id), "certreq") {
				t.Errorf("%s declares or references %s: Local-TLS has no certreq path", file, id)
			}
		}
		for _, lit := range literals {
			if strings.Contains(strings.ToLower(lit), "certreq") {
				t.Errorf("%s contains the string %s: Local-TLS runs no certreq", file, lit)
			}
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

// recordingKeyAPI is a cngKeyAPI fake that records every call and never
// touches a machine key.
type recordingKeyAPI struct {
	calls []string
	err   error
}

func (r *recordingKeyAPI) api() cngKeyAPI {
	signer := func(op, name string, p windowscng.Policy) (windowscng.Signer, error) {
		r.calls = append(r.calls, op+" "+name+" "+p.String())
		if r.err != nil {
			return nil, r.err
		}
		return newFakeCloseSigner(), nil
	}
	return cngKeyAPI{
		open: func(name string, p windowscng.Policy) (windowscng.Signer, error) {
			return signer("open", name, p)
		},
		create: func(name string, p windowscng.Policy) (windowscng.Signer, error) {
			return signer("create", name, p)
		},
		delete: func(name string, p windowscng.Policy, spki []byte) error {
			r.calls = append(r.calls, "delete "+name+" "+p.String()+" "+string(spki))
			return r.err
		},
	}
}

// TestProductionKeyOperationsUseRolePolicy proves that open, create and delete
// pass exactly the role policy of each key to windowscng, and the expected
// SPKI unchanged to delete.
func TestProductionKeyOperationsUseRolePolicy(t *testing.T) {
	rec := &recordingKeyAPI{}
	api := rec.api()
	for _, name := range []string{caKeyName, serverKeyName} {
		if _, err := openProductionKeyWith(api, name); err != nil {
			t.Fatal(err)
		}
		if _, err := createProductionKeyWith(api, name); err != nil {
			t.Fatal(err)
		}
		if err := deleteProductionKeyWith(api, name, []byte("spki-"+name)); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"open " + caKeyName + " privileged-only",
		"create " + caKeyName + " privileged-only",
		"delete " + caKeyName + " privileged-only spki-" + caKeyName,
		"open " + serverKeyName + " service-signer",
		"create " + serverKeyName + " service-signer",
		"delete " + serverKeyName + " service-signer spki-" + serverKeyName,
	}
	if strings.Join(rec.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(rec.calls, "\n"), strings.Join(want, "\n"))
	}
}

// TestProductionKeyOperationsRejectUnknownName proves no windowscng call is
// made for a name without a role policy.
func TestProductionKeyOperationsRejectUnknownName(t *testing.T) {
	rec := &recordingKeyAPI{}
	api := rec.api()
	name := identity.TestKeyNamespace + "Unknown"
	if _, err := openProductionKeyWith(api, name); err == nil {
		t.Error("open of an unknown name succeeded")
	}
	if _, err := createProductionKeyWith(api, name); err == nil {
		t.Error("create of an unknown name succeeded")
	}
	if err := deleteProductionKeyWith(api, name, []byte("spki")); err == nil {
		t.Error("delete of an unknown name succeeded")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("windowscng called for an unknown name: %v", rec.calls)
	}
}

// TestProductionKeyOperationsMapPolicyErrors proves that the windowscng
// failures of every operation reach callers as Local-TLS sentinels, with the
// windowscng sentinel still in the chain.
func TestProductionKeyOperationsMapPolicyErrors(t *testing.T) {
	for _, tc := range []struct {
		cngErr error
		want   error
	}{
		{fmt.Errorf("key %q: NCryptOpenKey hr=0x80090016: %w", caKeyName, windowscng.ErrKeyNotFound), ErrKeyNotFound},
		{fmt.Errorf("key %q (privileged-only): %w: persisted DACL is service-signer", caKeyName, windowscng.ErrPolicyMismatch), ErrKeyPolicyMismatch},
		{windowscng.ErrPrivilegeRequired, ErrPrivilegeRequired},
	} {
		rec := &recordingKeyAPI{err: tc.cngErr}
		api := rec.api()
		if _, err := openProductionKeyWith(api, caKeyName); !errors.Is(err, tc.want) || !errors.Is(err, tc.cngErr) {
			t.Errorf("open: %v, want %v and the cng error", err, tc.want)
		}
		if _, err := createProductionKeyWith(api, caKeyName); !errors.Is(err, tc.want) || !errors.Is(err, tc.cngErr) {
			t.Errorf("create: %v, want %v and the cng error", err, tc.want)
		}
		if err := deleteProductionKeyWith(api, caKeyName, []byte("spki")); !errors.Is(err, tc.want) || !errors.Is(err, tc.cngErr) {
			t.Errorf("delete: %v, want %v and the cng error", err, tc.want)
		}
	}
}

// TestMapCNGErrorKeyExists proves that a create collision maps to ErrKeyExists
// with the native NTE_EXISTS status still reachable.
func TestMapCNGErrorKeyExists(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptCreatePersistedKey", Code: windowscng.NTEExists}
	err := mapCNGError(fmt.Errorf("key %q: %w", caKeyName, errors.Join(windowscng.ErrKeyExists, native)))
	if !errors.Is(err, ErrKeyExists) || !errors.Is(err, windowscng.ErrKeyExists) {
		t.Fatalf("mapped %v, want ErrKeyExists at both levels", err)
	}
	var got *windowscng.NCryptError
	if !errors.As(err, &got) || got.Code != windowscng.NTEExists {
		t.Fatalf("mapped %v lost the native NTE_EXISTS", err)
	}
	for _, s := range []error{ErrKeyNotFound, ErrKeyPolicyMismatch, ErrPrivilegeRequired, ErrDeleteVerificationFailed} {
		if errors.Is(err, s) {
			t.Fatalf("a create collision mapped to %v", s)
		}
	}
}

// TestMapCNGErrorDeleteVerification proves that a failed pre-delete
// verification maps to ErrDeleteVerificationFailed, which takes precedence over
// the policy mismatch it may carry, and is never ErrKeyNotFound.
func TestMapCNGErrorDeleteVerification(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{"SPKI mismatch", fmt.Errorf("%w: public key differs from the expected SPKI", windowscng.ErrDeleteVerificationFailed)},
		{"policy mismatch", fmt.Errorf("%w: %w", windowscng.ErrDeleteVerificationFailed, windowscng.ErrPolicyMismatch)},
		{"check not completed", errors.Join(windowscng.ErrDeleteVerificationFailed, &windowscng.NCryptError{Op: "NCryptGetProperty(Export Policy)", Code: windowscng.NTEPerm})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := mapCNGError(tc.cause)
			if !errors.Is(err, ErrDeleteVerificationFailed) || !errors.Is(err, windowscng.ErrDeleteVerificationFailed) {
				t.Fatalf("mapped %v, want ErrDeleteVerificationFailed at both levels", err)
			}
			for _, s := range []error{ErrKeyNotFound, ErrKeyPolicyMismatch, ErrKeyExists} {
				if errors.Is(err, s) {
					t.Fatalf("a failed delete verification mapped to %v", s)
				}
			}
		})
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

// TestMapCNGErrorTypedNativeErrors proves the typed native errors of cng v0.3.0
// and later are passed through unchanged: a bare NCryptError is never promoted
// to ErrKeyNotFound (even for the not-found/bad-keyset statuses, because only the
// windowscng.ErrKeyNotFound sentinel classifies a key as not found or
// inaccessible), nor to a policy or privilege sentinel, and stays reachable with
// errors.As.
func TestMapCNGErrorTypedNativeErrors(t *testing.T) {
	for _, code := range []uint32{windowscng.NTEPerm, windowscng.NTEBadKeyset, windowscng.NTENotFound} {
		native := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: code}
		err := mapCNGError(fmt.Errorf("key %q: %w", caKeyName, native))
		var got *windowscng.NCryptError
		if !errors.As(err, &got) || got.Code != code {
			t.Fatalf("code 0x%x: native error lost in %v", code, err)
		}
		for _, s := range []error{ErrKeyNotFound, ErrKeyPolicyMismatch, ErrPrivilegeRequired} {
			if errors.Is(err, s) {
				t.Fatalf("code 0x%x: bare native error mapped to %v", code, s)
			}
		}
	}
}

// TestMapCNGErrorPostWriteVerification proves ErrPostWriteVerification (public
// since cng v0.3.0) is passed through unchanged: it is not turned into a
// Local-TLS sentinel, so the persisted-but-unverified DACL state is never
// reported as a mismatch, as a missing key or as a privilege problem.
//
// Scope: only the mapper is exercised, with NTE_PERM as the native cause; the
// NTE_BAD_KEYSET/NTE_NOT_FOUND causes and the absence of any later signer,
// create or retry in the callers are not covered here.
func TestMapCNGErrorPostWriteVerification(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptGetProperty(Security Descr)", Code: windowscng.NTEPerm}
	cause := errors.Join(windowscng.ErrPostWriteVerification, native)
	err := mapCNGError(fmt.Errorf("key %q: %w", caKeyName, cause))
	if !errors.Is(err, windowscng.ErrPostWriteVerification) {
		t.Fatalf("mapped %v lost ErrPostWriteVerification", err)
	}
	var got *windowscng.NCryptError
	if !errors.As(err, &got) || got.Code != windowscng.NTEPerm {
		t.Fatalf("mapped %v lost the native cause", err)
	}
	for _, s := range []error{ErrKeyNotFound, ErrKeyPolicyMismatch, ErrPrivilegeRequired} {
		if errors.Is(err, s) {
			t.Fatalf("post-write verification failure mapped to %v", s)
		}
	}
}

// TestMapCNGErrorUnavailableDescriptor proves a persisted-DACL read that CNG
// v0.3.1 reports as unavailable (it no longer wraps ErrPolicyMismatch) stays an
// unclassified error: it is not mapped to ErrKeyPolicyMismatch and, being
// neither not-found nor a privilege problem, not to those sentinels either, so
// the callers keep failing closed without treating it as a policy decision.
//
// Scope: the cause is a synthetic error carrying the expected message, so this
// proves only the mapper's pass-through of an unclassified error. It does not
// prove that a native 0-byte read yields that classification (covered by the
// cng module's own tests) nor the behavior of the callers. A failure after the
// DACL write is a different case, reported as ErrPostWriteVerification (see
// TestMapCNGErrorPostWriteVerification).
func TestMapCNGErrorUnavailableDescriptor(t *testing.T) {
	cause := errors.New("read persisted DACL (descriptor unavailable): NCryptGetProperty(Security Descr): reported 0 bytes written")
	err := mapCNGError(fmt.Errorf("key %q: %w", caKeyName, cause))
	if err == nil {
		t.Fatal("unavailable descriptor mapped to nil")
	}
	for _, s := range []error{ErrKeyNotFound, ErrKeyPolicyMismatch, ErrPrivilegeRequired} {
		if errors.Is(err, s) {
			t.Fatalf("unavailable descriptor mapped to %v", s)
		}
	}
	if !errors.Is(err, cause) {
		t.Fatalf("mapped %v lost the original error", err)
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
// the Local-TLS ErrKeyNotFound contract and stays reachable in the chain.
func TestMapCNGErrorNotFound(t *testing.T) {
	err := mapCNGError(windowscng.ErrKeyNotFound)
	if !errors.Is(err, ErrKeyNotFound) || !errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatalf("mapCNGError(windowscng.ErrKeyNotFound) = %v, want ErrKeyNotFound at both levels", err)
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
// name and native HRESULT of the windowscng error, and its native
// *NCryptError, while matching ErrKeyNotFound.
func TestMapCNGErrorKeepsNativeHRESULT(t *testing.T) {
	native := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset}
	underlying := fmt.Errorf("key %q: %w", serverKeyName, errors.Join(windowscng.ErrKeyNotFound, native))
	err := mapCNGError(underlying)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mapped error must match ErrKeyNotFound: %v", err)
	}
	var got *windowscng.NCryptError
	if !errors.As(err, &got) || got.Code != windowscng.NTEBadKeyset {
		t.Fatalf("mapped error %v lost the native cause", err)
	}
	if !strings.Contains(err.Error(), serverKeyName) {
		t.Fatalf("mapped error %q lost the key name", err)
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
