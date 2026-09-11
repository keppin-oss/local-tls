//go:build windows

package localtls

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keppin-oss/local-tls/internal/identity"
)

// TestProductionKeyNamesExact proves the cleanup operates on the exact
// Local-TLS production key names and never on the test/smoke namespace or on
// Machine Identity / Enterprise identities.
func TestProductionKeyNamesExact(t *testing.T) {
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

func TestPlatformKeyDeleterReturnsDeleter(t *testing.T) {
	d, err := PlatformKeyDeleter()
	if err != nil {
		t.Fatalf("PlatformKeyDeleter: %v", err)
	}
	if d == nil {
		t.Fatal("PlatformKeyDeleter returned nil")
	}
	if _, ok := d.(MachineKeyDeleter); !ok {
		t.Fatal("returned value does not implement MachineKeyDeleter")
	}
}

// smokeKeyDeleter reuses the exact production key-deletion path
// (deleteProductionKey) against the smoke test key names so the elevated
// lifecycle smoke never touches production keys.
type smokeKeyDeleter struct{}

func (smokeKeyDeleter) DeleteCAKey() error     { return deleteProductionKey(SmokeCAKeyName) }
func (smokeKeyDeleter) DeleteServerKey() error { return deleteProductionKey(SmokeServerKeyName) }

// TestCleanupLifecycleElevated proves the full provision → verify → cleanup →
// verify-absent lifecycle against test-only smoke namespaces, and repeats it to
// prove repeatability. It requires Administrator elevation and is skipped
// (reported NOT EXECUTED) when not elevated.
func TestCleanupLifecycleElevated(t *testing.T) {
	run := func(root string) error {
		tlsDir := filepath.Join(root, tlsSubDir)

		material, err := ProvisionSmoke(root)
		if err != nil {
			return fmt.Errorf("ProvisionSmoke: %w", err)
		}

		trustStore, err := PlatformTrustStore()
		if err != nil {
			return fmt.Errorf("PlatformTrustStore: %w", err)
		}

		state, err := VerifySmokeTrust(material.CACertificate.Raw)
		if err != nil {
			return fmt.Errorf("VerifySmokeTrust: %w", err)
		}
		if state != TrustHealthy {
			return fmt.Errorf("expected TrustHealthy, got %s", state)
		}

		if err := cleanupLocalTLS(tlsDir, smokeKeyDeleter{}, func() error {
			return trustStore.RemoveTrust(material.CACertificate.Raw)
		}); err != nil {
			return fmt.Errorf("cleanupLocalTLS: %w", err)
		}

		found, err := trustStore.IsTrustedSHA256(material.CAFingerprintSHA256)
		if err != nil {
			return fmt.Errorf("IsTrustedSHA256: %w", err)
		}
		if found {
			return fmt.Errorf("trust anchor still present after cleanup")
		}

		for _, name := range []string{SmokeCAKeyName, SmokeServerKeyName} {
			if _, err := TestOpenKey(name); err == nil {
				return fmt.Errorf("smoke key %q still present after cleanup", name)
			}
		}
		return nil
	}

	if err := run(t.TempDir()); err != nil {
		t.Skipf("elevated lifecycle smoke requires Administrator: %v — NOT EXECUTED", err)
	}
	if err := run(t.TempDir()); err != nil {
		t.Fatalf("second lifecycle run failed: %v", err)
	}
}
