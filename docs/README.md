# Local TLS — Technical Documentation

This is the technical reference for the `local-tls` module
(`github.com/keppin-oss/local-tls`, package `localtls`). It documents what the
module does, how it is structured, and — critically — the boundary of what is
guaranteed versus what is caller responsibility or best-effort.

Every claim in this document is traceable to the source, the tests, the build
tags, or `go.mod`. Where a behavior is not demonstrable from this repository, it
is labeled explicitly.

---

## How to read this document

Claims are marked with one of these categories:

- **Policy** — a required behavior the module enforces by design. Violating it
  is a bug.
- **Verified** — a property proven by this repository's tests.
- **Assumed** — a property provided by a dependency (not re-verified here).
- **Caller responsibility** — an obligation on the integrating code.
- **Best-effort** — a behavior that attempts an action but does not guarantee
  its outcome.

Do not turn accidental behavior or undocumented implementation details into a
public contract.

---

## Architecture

`local-tls` is a small, layered Go module. The production path is Windows-only
and composes three platform seams:

1. **Key custody** — `MachineKeyStore` / `MachineKeyDeleter`, backed on Windows
   by the Microsoft Software Key Storage Provider through the
   `github.com/keppin-oss/cng` module (`windowscng` package).
2. **Trust store** — `TrustProvisioner` / `TrustVerifier`, backed on Windows by
   `LocalMachine\Root` via CryptoAPI.
3. **Certificate material** — generated and validated in-process (`certificate.go`
   and `provision.go`); on the production machine path only public DER is
   persisted.

The composition layer (`composition_windows.go`) wires these seams into the
production entry points (`ProvisionMachine`, `ReloadMachine`,
`LoadServingMaterial`) and the cleanup entry points (`CleanupMachine`,
`CleanupMachineBySHA256`).

```
examples/            runnable, compile-safe examples
cmd/verify/          manual verification CLI (test namespace only)
internal/identity/   fixed persisted identity constants (key names, DNs, paths)
```

## Ownership boundary

`local-tls` **owns**:

- the Local TLS CA certificate and the `localhost` server certificate;
- the persisted CA and server CNG signing keys;
- the public certificate DER persisted under the machine TLS state directory;
- the exact local CA trust anchor in `LocalMachine\Root`;
- the exact cleanup of all of the above.

`local-tls` **does not own** (and must not be asked to own):

- enterprise CA enrollment or enterprise-vs-local selection policy;
- low-level reusable CNG/KSP key custody — that is the `github.com/keppin-oss/cng`
  module (`windowscng`);
- the long-lived HTTPS listener / server runtime;
- authorization, machine identity, tenant, installation, licensing, or unrelated
  application state.

It deliberately is **not** a generic TLS/PKI framework, certificate manager, or
trust-store framework.

## Requirements

- **Windows-only runtime** for production machine flows. The module still builds
  and tests on non-Windows via stubs, but the production machine functions return
  explicit unsupported-platform errors (see
  [Windows / platform behavior](#windows--platform-behavior)).
- **Administrator elevation** is required for `ProvisionMachine`, `CleanupMachine`,
  and `CleanupMachineBySHA256`. `LoadServingMaterial`, `ReloadMachine`, and
  read-only trust verification do not mutate machine trust and do not require
  elevation, but the calling process must be able to open the persisted server key
  (caller responsibility).
- **Microsoft Software Key Storage Provider** is the only supported key store.
- **Go** — the module declares `go 1.26.5`.

### Dependencies

```
github.com/keppin-oss/cng v0.1.2      // windowscng — CNG/KSP key custody
golang.org/x/sys        v0.47.0       // Windows syscall bindings
```

## Configuration

There is no runtime configuration file. The module's persisted identity is fixed
by constants in `internal/identity`:

| Constant | Value | Notes |
| --- | --- | --- |
| `FileSystemDir` | `Keppin` | machine state directory name |
| `ProdCAKeyName` | `Keppin.Agent.LocalHTTPS.CA.v1` | persisted CA CNG key |
| `ProdServerKeyName` | `Keppin.Agent.LocalHTTPS.Server.v1` | persisted server CNG key |
| `TestKeyNamespace` | `Keppin.Test.` | enforced prefix for all test keys |
| `SmokeKeyNamespace` | `Keppin.Test.Smoke.` | smoke-test key prefix |
| `CertOrganization` | `Keppin` | certificate Subject Organization |
| `CACertCommonName` | `Keppin Local Root CA` | CA Subject CN |

Machine state locations (resolved at runtime):

- `MachineAgentPath()` → `%ProgramData%\Keppin\Agent`
- `MachineTLSPath()` → `%ProgramData%\Keppin\Agent\tls`

These persisted identities are compatibility contracts: changing them after an
external release would create parallel identities and require migration. The
values above are **not** affected by the module/import rename and must not be
changed by documentation work.

## Public API

### Production machine entry points (Windows-only)

```go
func MachineAgentPath() (string, error)
func MachineTLSPath() (string, error)
func ProvisionMachine() (Material, error)
func ReloadMachine() (Material, error)
func LoadServingMaterial() (Material, error)
func CleanupMachine() error
func CleanupMachineBySHA256(fp [32]byte) error
```

`MachineAgentPath` / `MachineTLSPath` are read-only helpers exposing the
persisted locations; they are not mutation points.

### Material

```go
const RenewalThreshold = 30 * 24 * time.Hour // server-certificate renewal window

type Material struct {
	Certificate         tls.Certificate
	CACertificate       *x509.Certificate
	ServerCertificate   *x509.Certificate
	CAFingerprintSHA256 [32]byte
}

func (m *Material) Close() error
```

- `Certificate` is the server TLS serving material. On the production path its
  private signing operation is CNG-backed through `crypto.Signer`.
- `CACertificate` is the public CA material; `ServerCertificate` is the parsed
  public leaf.
- `CAFingerprintSHA256` is the exact SHA-256 identity of the local CA, useful for
  diagnostics and cleanup handoff.

### Key-store abstractions

```go
type MachineKeyStore interface {
	LoadOrCreateCAKey() (crypto.Signer, error)
	LoadOrCreateServerKey() (crypto.Signer, error)
}
type MachineKeyDeleter interface {
	DeleteCAKey() error
	DeleteServerKey() error
}
func PlatformKeyStore() (MachineKeyStore, error)
func PlatformKeyDeleter() (MachineKeyDeleter, error)

var ErrKeyNotFound error
```

`PlatformKeyStore` / `PlatformKeyDeleter` are the production platform seams the
entry points compose through. They are not intended for consumers to swap out the
production CNG path. `ErrKeyNotFound` is the sentinel for an absent exact
persisted CNG key; match it with `errors.Is`.

### Trust APIs

```go
type TrustState int
const (
	TrustHealthy TrustState = iota
	TrustAbsent
	TrustConflict
	TrustError
)

func (s TrustState) String() string

type TrustProvisioner interface {
	InstallTrust(certificateDER []byte) error
	RemoveTrust(certificateDER []byte) error
	RemoveTrustBySHA256(fp [32]byte) error
}
type TrustVerifier interface {
	VerifyTrust(certificateDER []byte) (TrustState, error)
	IsTrustedSHA256(fingerprint [32]byte) (bool, error)
}
type TrustStore interface {
	TrustProvisioner
	TrustVerifier
	EnsureTrusted(certificateDER []byte) error // Deprecated
}

func PlatformTrustStore() (TrustStore, error)
func ComputeSHA256Fingerprint(der []byte) [32]byte
func ParseSHA256Fingerprint(hexFP string) ([32]byte, error)

var ErrTrustAnchorNotFound error
```

- Mutating operations (`TrustProvisioner`) are elevated provisioning/repair
  concerns. Read-only verification (`TrustVerifier`) is safe for normal runtime.
- `TrustStore` is a backward-compatibility combined interface; `EnsureTrusted` is
  **deprecated**. New code should use `TrustProvisioner` and `TrustVerifier`
  separately.
- `ComputeSHA256Fingerprint` returns the SHA-256 identity of a DER certificate.
- `ParseSHA256Fingerprint` parses a 64-hex-character fingerprint (surrounding
  whitespace tolerated, case-insensitive) into a `[32]byte`.
- `ErrTrustAnchorNotFound` is the sentinel for an absent exact trust anchor; match
  it with `errors.Is`.

### Legacy / testing APIs

```go
type Protector interface {
	Protect(plaintext []byte) ([]byte, error)
	Unprotect(ciphertext []byte) ([]byte, error)
}
func PlatformProtector() (Protector, error) // returns an error (not configured)

func Provision(dataDir string, protector Protector, trustStore TrustStore, now func() time.Time) (Material, error)
func ProvisionWithKeyStore(dataDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error)
```

- `Provision` is the legacy **Protector-based** path, kept for backwards-compatible
  tests that use exported private keys. It persists protected private-key material
  and is **not** the production flow. Do not teach it as the normal production
  path.
- `ProvisionWithKeyStore` is the key-store-based provisioning seam (also used by
  `ProvisionMachine`). It is exported but is a lower-level seam, not the preferred
  consumer entry point.
- `PlatformProtector` currently returns an error: the production machine path uses
  CNG/KSP key custody rather than the protector-based path, so machine key
  protection is not configured.

The package also exports Windows-only test/smoke helpers (`TestCreateKey`,
`TestOpenKey`, `TestDeleteKey`, `TestSignAndVerify`, `ProvisionSmoke`,
`CleanupSmoke`, `VerifySmokeTrust`, `CleanupSmokeAnchorBySHA256`,
`SmokeCAKeyName`, `SmokeServerKeyName`) scoped to the `Keppin.Test.*` namespace.
These are testing surfaces, not production APIs.

## Provisioning flow

`ProvisionMachine()` (Windows-only, elevated) performs first install or repair:

1. resolves `MachineAgentPath()`;
2. **fails closed** on any partial or incoherent pre-existing state — one
   certificate DER present without the other, a persisted key with no certificate
   material, or certificate material whose persisted keys are missing or
   unopenable — rather than silently regenerating a CA or creating replacement
   keys (policy; guarded by `checkInconsistentMachineState`, which is open-only);
3. creates or opens the persisted CA and server CNG keys;
4. creates and persists public CA and server certificate DER only (production
   machine path);
5. installs the exact local CA into `LocalMachine\Root` (idempotent);
6. preserves the existing CA identity across repeated healthy provisioning, and
   renews the server certificate only when required, reusing the existing
   persisted server key.

`LoadServingMaterial()` is the preferred serving-startup path:

- loads CA and server public DER;
- opens **only the server CNG key** (never the CA key);
- verifies server cert ↔ server key, issuer, and SANs;
- performs read-only trust verification and fails closed unless the CA is
  `TrustHealthy`;
- does **not** renew the server certificate and does not check its expiry — use
  `ReloadMachine` for the maintenance/renewal path;
- does not mutate `LocalMachine\Root`.

`ReloadMachine()` is the broader maintenance/reload path:

- opens **both** the CA and server keys;
- verifies cert/key/issuer/SAN/trust state;
- does not mutate `LocalMachine\Root`;
- may renew the server certificate when near/past expiry (reusing the persisted
  server key).

### Decision guide

| Need | Preferred API | Elevation / mutation |
| --- | --- | --- |
| First install / repair | `ProvisionMachine()` | Administrator; may create keys, write DER, install trust |
| Normal serving startup | `LoadServingMaterial()` | No trust mutation; opens server key only |
| Reload + possible renewal | `ReloadMachine()` | No trust mutation; opens CA + server keys; may rewrite server DER |
| Exact cleanup (DER available) | `CleanupMachine()` | Administrator; destructive |
| Cleanup by fingerprint | `CleanupMachineBySHA256(fp)` | Administrator; destructive |

## Certificate & key lifecycle

Verified properties of the generated material:

- CA and server keys are **ECDSA P-256**.
- CA certificate is **self-signed**: `IsCA`, `BasicConstraintsValid`,
  `MaxPathLen=0` (`MaxPathLenZero=true`), key usage restricted to
  `KeyUsageCertSign` only (no `CRLSign`, no `DigitalSignature`).
- Server certificate is signed by that CA; server-auth EKU only.
- Server identity is strictly local: DNS SAN `localhost`; IP SANs `127.0.0.1`
  and `::1` (validated by `validateSAN`).
- CA validity is **5 years**; server validity is **90 days**; renewal triggers
  when the server certificate is within `RenewalThreshold` (**30 days**) of
  expiry or already expired.
- Renewal **reuses** the existing persisted server key — key rotation is
  decoupled from certificate renewal (verified by
  `TestRenewalViaKeyStorePreservesCAAndServerKey`).
- The CA `MaxPathLen=0` constraint rejects subordinate-CA chains (verified by
  `TestSubordinateCAChainRejected`).

Key custody differs between the two provisioning paths:

- **Production machine (CNG) path** (`ProvisionMachine`, `LoadServingMaterial`,
  `ReloadMachine`): the module never receives private-key bytes — it operates on
  `crypto.Signer` handles only, and persists only the public certificate DER
  (`ca-cert.der`, `server-cert.der`) (policy; verified by construction).
- **Legacy Protector path** (`Provision`): persists serialized private-key
  material through a `Protector` seam (`ca-key.enc`, `server-key.enc`) alongside
  the public DER. This is not the production flow. `Protector` is a seam — this
  repository does not guarantee that a given implementation actually encrypts the
  bytes it receives.
- Non-exportable, machine-scoped, persistent keys are provided by
  `github.com/keppin-oss/cng` (assumed — enforced by the CNG layer, not
  re-verified here).

## Trust-store behavior

The Windows trust adapter targets `LocalMachine\Root`:

- `InstallTrust` is idempotent — it matches by exact SHA-256 fingerprint and does
  not duplicate (verified).
- `RemoveTrust` / `RemoveTrustBySHA256` remove by exact identity; removal is by
  exact SHA-256 only, never by subject/CN, wildcard, or prefix (policy).
- `VerifyTrust` is read-only and returns:
  - `TrustHealthy` — exact CA present;
  - `TrustConflict` — same-subject certificate with a different fingerprint
    (manual resolution required; never auto-remove);
  - `TrustAbsent` — CA not present;
  - `TrustError` — verification itself failed.
- `IsTrustedSHA256` reports exact-fingerprint presence.

Trust verification uses exact CA identity, not loose subject-name trust. A
conflicting certificate (same CN, different fingerprint) is reported as
`TrustConflict` (verified).

## Cleanup behavior

`CleanupMachine()` and `CleanupMachineBySHA256(fp)` remove, in order, on a
best-effort basis across independently removable artifacts:

1. the exact local CA trust anchor from `LocalMachine\Root`;
2. the exact local CA CNG key;
3. the exact local server CNG key;
4. the Local TLS state directory (`...\Agent\tls`).

Failure semantics:

- a failure on one artifact does not stop removal of the others (best-effort);
- failures not attributable to "already absent" are aggregated with `errors.Join`
  so no security-sensitive artifact failure is silently swallowed (verified);
- already-absent exact artifacts are idempotent success via `ErrKeyNotFound` and
  `ErrTrustAnchorNotFound`;
- cleanup never deletes by subject/CN, wildcard, prefix, or unrelated parent
  directory.

`CleanupMachine` needs the on-disk CA DER to identify the trust anchor. If the
state directory (and thus the DER) is already gone, use
`CleanupMachineBySHA256` with the known fingerprint.

## Security model

- On the production machine path, private keys are machine-scoped and never
  persisted as files; the module never handles private-key bytes on that path.
  (The legacy Protector path is the exception: it persists private-key material
  through the `Protector` seam.)
- The CA is a path-length-zero, sign-only CA used exclusively to issue the local
  `localhost` server certificate.
- Trust is anchored on exact SHA-256 identity, not subject name.
- Missing or conflicting trust, cert/key mismatch, unexpected issuer, and invalid
  SAN all fail closed.
- **No example or consumer guidance may set `InsecureSkipVerify`, disable
  hostname verification, ignore trust state, or bypass the module's verification
  policy** (policy).

## Lifecycle & ownership of `Material`

- Before a successful return, the module owns the signer handles and closes every
  handle it opens on error paths (verified).
- After a successful return, the caller owns the serving signer and must call
  `Close()` (caller responsibility).
- The CA signer is a transient internal handle used only for issuer/renewal
  signing; it is never transferred to the caller and is released internally.
- `Close()` releases the process-local CNG handle only. It never deletes a
  persisted key, never removes certificates or trust anchors, and never triggers
  cleanup (verified).
- `Close()` is idempotent in effect (verified). After `Close()`, the serving
  certificate must not be used for new handshakes.
- `Material` is single-owner; do not copy it by value and reuse the copy after
  `Close`.

## Windows / platform behavior

- Production machine functions are Windows-only (`//go:build windows`).
- On non-Windows (`//go:build !windows`), the machine functions
  (`MachineAgentPath`, `MachineTLSPath`, `ProvisionMachine`, `ReloadMachine`,
  `LoadServingMaterial`, `CleanupMachine`, `CleanupMachineBySHA256`) and the
  platform seams (`PlatformKeyStore`, `PlatformKeyDeleter`,
  `PlatformTrustStore`) return explicit unsupported-platform errors.
- The `localtls` package itself remains buildable/testable on non-Windows via
  stubs; only the production machine functions are Windows-only. The Windows-only
  commands (`cmd/verify`, `examples/provision`, `examples/serving`) carry
  `//go:build windows`, so the full `go build ./...` is cross-platform.

## Examples

- [`examples/serving`](../examples/serving/main.go) — `LoadServingMaterial()` →
  fail-closed error check → `Material.Certificate` in `tls.Config`. Loopback-only;
  never mutates trust; never opens the CA key; no `InsecureSkipVerify`.
  Windows-only.
- [`examples/provision`](../examples/provision/main.go) — elevated
  `ProvisionMachine()` and inspection of the returned public metadata. Mutates
  machine CNG state and `LocalMachine\Root`; must not run in normal tests.
  Windows-only.
- [`examples/fingerprint`](../examples/fingerprint/main.go) — non-destructive
  demonstration of `ComputeSHA256Fingerprint`, `ParseSHA256Fingerprint`, and the
  `CleanupMachine` vs `CleanupMachineBySHA256` handoff decision. Cross-platform.

## Validation

Default validation path (cross-platform; Windows-specific tests run only on
Windows and skip when not elevated):

```text
go build ./...
go vet ./...
go test ./...
```

Elevated Windows validation for the CNG / trust-store / cleanup lifecycle is
provided by Windows-specific tests that skip when not running as Administrator:

```text
go test -v ./... -run 'TestCleanupLifecycleElevated|TestTrustStore'
```

Live flows requiring elevation, machine CNG state, and `LocalMachine\Root`
mutation are reported **NOT EXECUTED** in unprivileged environments and must be
validated manually on a disposable Windows environment.

## Limitations

- **Windows-only** for production machine flows.
- **Microsoft Software KSP only** — no other key provider is supported.
- The legacy Protector path is **not** the production path; `PlatformProtector`
  returns an error because machine key protection is not configured.
- Trust-conflict resolution is **manual** — the module never auto-removes a
  conflicting anchor.
- The module does not provide a generic TLS/PKI or trust-store framework.

## Troubleshooting

1. **Platform** — is this Windows? On non-Windows the machine functions return
   explicit unsupported-platform errors.
2. **Provisioning** — was `ProvisionMachine()` already run (elevated)? Serving
   startup requires previously persisted machine material.
3. **Elevation** — provisioning and cleanup require Administrator; serving
   startup and read-only verification do not, but the process must be able to
   open the persisted server key.
4. **Trust** — `TrustAbsent` / `TrustConflict` fails closed; do not weaken trust
   checks and do not auto-remove a conflicting anchor.
5. **Sentinels** — match with `errors.Is(err, localtls.ErrKeyNotFound)` /
   `errors.Is(err, localtls.ErrTrustAnchorNotFound)`.
