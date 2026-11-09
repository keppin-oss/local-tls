# Local TLS — Technical Documentation

This is the technical reference for the `local-tls` module
(`github.com/keppin-oss/local-tls`, package `localtls`). It documents what the
module does, how it is structured, and — critically — the boundary of what is
guaranteed versus what is caller responsibility or best-effort.

Every claim in this document is traceable to the source, the tests, the build
tags, or `go.mod`. Where a behavior is not demonstrable from this repository, it
is labeled explicitly.

This document describes **v0.3.0**. Upgrading from v0.2.x? Read
[Upgrading from v0.2.x to v0.3.0](#upgrading-from-v02x-to-v030) first: v0.3.0
changes who may call several entry points and requires an explicit, privileged
key-ACL migration on existing installations. Upgrading from v0.1.x? Also read
[Upgrading from v0.1.x](#upgrading-from-v01x): v0.2.0 contains intentional
breaking behavior changes.

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
3. **Certificate material** — generated and validated in-process
   (`certificate.go`, `validate.go`, `provision.go`, `renewal.go`); only public
   DER is persisted.

The composition layer (`composition_windows.go`) wires these seams into the
production entry points (`ProvisionMachine`, `ReloadMachine`,
`LoadServingMaterial`), the staged renewal entry points (`StageServerRenewal`,
`LoadServingCandidate`, `ConfirmServingCandidate`, `AbandonServingCandidate`)
and the cleanup entry points (`CleanupMachine`, `CleanupMachineBySHA256`).

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
- the long-lived HTTPS listener / server runtime, including activation of a
  renewed certificate in that listener;
- authorization, machine identity, tenant, installation, licensing, or unrelated
  application state.

It deliberately is **not** a generic TLS/PKI framework, certificate manager, or
trust-store framework.

## Requirements

- **Windows-only runtime** for production machine flows. The module still builds
  and tests on non-Windows via stubs, but the production machine functions return
  explicit unsupported-platform errors (see
  [Windows / platform behavior](#windows--platform-behavior)).
- **Administrative operations** — `ProvisionMachine`, `ReloadMachine`,
  `StageServerRenewal`, `MigrateMachineKeyPolicies`, `CleanupMachine` and
  `CleanupMachineBySHA256` must be called by LocalSystem or an elevated
  Administrators member (caller responsibility). The first four open the
  privileged-only CA key and fail closed otherwise (policy; see
  [Key access policies](#key-access-policies)); cleanup needs the same
  authority to delete the keys and the trust anchor.
- **Serving operations** — `LoadServingMaterial` and `LoadServingCandidate`
  need a principal that the server key DACL actually authorizes (in practice
  LOCAL SERVICE, LocalSystem or an elevated Administrator) plus read access to
  the TLS state files. "Not elevated" does not mean "authorized": a
  UAC-filtered Administrator token cannot open the server key either.
- **Renewal consumer steps** — `ConfirmServingCandidate` needs **both** access to
  the server key and the filesystem rights listed in
  [Filesystem access](#filesystem-access); `AbandonServingCandidate` opens no key
  but needs the filesystem rights for its files. See
  [Privilege and access matrix](#privilege-and-access-matrix).
- **Filesystem ACLs** on the TLS state directory are set by the installer or
  updater, not by Local TLS (caller responsibility; see
  [Filesystem access](#filesystem-access)).
- **Single lifecycle writer** (caller responsibility). One lifecycle coordinator
  per machine must ensure that provisioning, cleanup/uninstall, administrative
  recovery and every server-certificate renewal attempt (the whole sequence
  `StageServerRenewal` → `LoadServingCandidate` → consumer activation and
  attestation → `ConfirmServingCandidate` or `AbandonServingCandidate`) never
  overlap, and that no other actor creates, deletes or re-permissions the
  Local TLS key names or state directory while they run. The key-ACL migration
  (`MigrateMachineKeyPolicies`) is part of the same serialization. Local TLS
  does **not** implement or verify this serialization. The digest checks of the
  renewal API detect some violations, not all; they are not a lock.
- **Microsoft Software Key Storage Provider** is the only supported key store.
- **Go** — the module declares `go 1.26.8`.

### Dependencies

```
github.com/keppin-oss/cng v0.2.1      // windowscng — CNG/KSP key custody
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

Files in the TLS state directory:

| File | Meaning |
| --- | --- |
| `ca-cert.der` | the CA certificate (public DER) |
| `server-cert.der` | the **persisted** server certificate: what `LoadServingMaterial` loads |
| `server-cert.pending.der` | a staged, validated renewal candidate; never served by `LoadServingMaterial` |
| `server-cert.prev.der` | single-slot copy of the persisted server certificate taken before the last promotion; not a history |

These persisted identities are compatibility contracts: changing them after an
external release would create parallel identities and require migration. They
are unchanged from v0.1.x and must not be changed by documentation work.

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

// Explicit, privileged key-ACL migration for installations provisioned before
// the CA key was separated from the server signer
func MigrateMachineKeyPolicies() error

// Staged server-certificate renewal
func StageServerRenewal() (CandidateRef, error)
func LoadServingCandidate(ref CandidateRef) (Material, error)
func ConfirmServingCandidate(ref CandidateRef) error
func AbandonServingCandidate(ref CandidateRef) error
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

### Renewal types

```go
type RenewalOutcome int
const (
	RenewalNotDue RenewalOutcome = iota + 1 // the zero value is not a valid outcome
	RenewalCandidateStaged
)
func (o RenewalOutcome) String() string

type CandidateRef struct {
	Outcome         RenewalOutcome
	CandidateSHA256 [32]byte
	BaseSHA256      [32]byte
	CASHA256        [32]byte
}
```

### Errors

All sentinels are matched with `errors.Is`; returned errors wrap them with
context, and a single error can match more than one sentinel.

```go
var (
	ErrCertificateNotValidNow   error // CA or leaf expired or not yet valid
	ErrLeafOutlivesCA           error // leaf validity would extend beyond the CA
	ErrTrustNotHealthy          error // CA trust anchor absent or conflicting
	ErrInconsistentMachineState error // partial or incoherent persisted state
	ErrRenewalDue               error // run the staged renewal flow

	ErrNoCandidate          error
	ErrCandidateNotFound    error
	ErrCandidateMismatch    error
	ErrCandidateStale       error
	ErrCandidatePromoted    error
	ErrPromotionUnconfirmed error

	ErrKeyNotFound            error // CNG key not found OR not accessible
	ErrKeyPolicyMismatch      error // key DACL is not its role policy; key unchanged
	ErrPrivilegeRequired      error // CA key or migration needs SYSTEM/elevated Administrators
	ErrKeyDeletionUnconfirmed error // cleanup could not confirm a key deletion
	ErrTrustAnchorNotFound    error // exact trust anchor already absent
)
```

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
```

`PlatformKeyStore` / `PlatformKeyDeleter` are the production platform seams the
entry points compose through. They are not intended for consumers to swap out the
production CNG path. `ErrKeyNotFound` means the native open of the exact
persisted key reported it as **not found or not accessible**: it does **not**
prove that the key is absent, and it must never by itself trigger a reset,
regeneration or overwrite of a key (policy). Its message keeps the native
HRESULT.

### Key access policies

Each production key has its own DACL policy, applied through the policy-aware
API of `github.com/keppin-oss/cng/windowscng` (`OpenWithPolicy`,
`LoadOrCreateWithPolicy`, `ApplyPolicy`):

| Key | Policy | DACL | Who can open it |
| --- | --- | --- | --- |
| CA key | `PolicyPrivilegedOnly` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | LocalSystem, elevated Administrators |
| Server key | `PolicyServiceSigner` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)` | the above and **any** process running as LOCAL SERVICE |

The Microsoft Software KSP stores the expanded access masks rather than the
generic rights requested (`GA` is read back as `0xd01f01ff`, `GRGX` as
`0x801200a9`); `windowscng` normalizes them when it compares a DACL with a
policy. This was observed on a real Windows 11 KSP (see
[Windows validation of the key policies](#windows-validation-of-the-key-policies)).

- Every open verifies that the persisted DACL is **exactly** the role policy;
  anything else fails closed with `ErrKeyPolicyMismatch` and the key is not
  modified.
- Creation happens only on first install, only for a privileged caller, and only
  when the native open reports the key as not found; any other open failure is
  returned without creating a key.
- `CleanupMachine` deletes by exact name and does not depend on the policy.
- Installations provisioned before v0.3.0 have a CA key with the server signer
  DACL. Serving keeps working on them, but `ProvisionMachine`, `ReloadMachine`
  and `StageServerRenewal` fail with `ErrKeyPolicyMismatch` until an elevated
  caller runs `MigrateMachineKeyPolicies` once. Local-TLS never migrates
  implicitly. See [Upgrading from v0.2.x to v0.3.0](#upgrading-from-v02x-to-v030).

What these policies do and do not isolate:

- **CA key vs. server signer.** After migration (or on a v0.3.0 first install),
  no LOCAL SERVICE process can open the CA key; only the server key is usable by
  a non-privileged runtime.
- **Shared LOCAL SERVICE identity.** The server key DACL grants the shared
  well-known LOCAL SERVICE SID (`S-1-5-19`), not a dedicated Agent identity.
  Every process running as LOCAL SERVICE on the machine can use the server
  signing key. Local TLS does **not** isolate the Agent from other LOCAL SERVICE
  processes, and v0.3.0 introduces no service-specific SID.
- **UAC-filtered Administrators.** In a filtered (non-elevated) token the
  Administrators group is deny-only, so the `BA` entry does not apply: such a
  caller can open **neither** key. Authorization depends on the effective
  token, not on whether the account is an administrator.
- **Before migration, the CA key is still exposed.** A legacy CA key keeps its
  LOCAL SERVICE entry until `MigrateMachineKeyPolicies` succeeds. The v0.3.0
  API refuses to use it, but any LOCAL SERVICE process can still open it
  through the native CNG API. Upgrading the library **without** running the
  migration does not mitigate that exposure.
- **Open handles.** Rewriting the CA key DACL denies new opens; it is not
  assumed to revoke handles that a process already holds. See the cutover
  procedure in [Upgrading from v0.2.x to v0.3.0](#upgrading-from-v02x-to-v030).

### Privilege and access matrix

"Privileged" means LocalSystem or an elevated Administrators member. "Server
key principal" means a token that the server key DACL actually authorizes
(LOCAL SERVICE, LocalSystem, elevated Administrators). The filesystem column
names what the operation does on the TLS state directory; the rights it implies
are listed in [Filesystem access](#filesystem-access).

| Operation | Caller | Keys opened | TLS state directory | `LocalMachine\Root` |
| --- | --- | --- | --- | --- |
| `ProvisionMachine` (first install) | privileged | CA + server, created under their role policies | creates the directory; writes `ca-cert.der`, `server-cert.der` via temporaries + rename | installs the exact CA |
| `ProvisionMachine` (existing state) | privileged | CA + server through the `MachineKeyStore` open-or-create seam | reads only | read-only verification |
| `ReloadMachine` | privileged | CA + server, open-only | reads `ca-cert.der`, `server-cert.der` | read-only verification |
| `StageServerRenewal` | privileged | CA (signs) + server (verifies), open-only | reads DER; creates/replaces/deletes `server-cert.pending.der`; creates and removes `.localtls-tmp-*` | read-only verification |
| `MigrateMachineKeyPolicies` | privileged | server (verify only), CA (DACL rewritten, then verified) | reads `ca-cert.der`, `server-cert.der` | not touched |
| `LoadServingMaterial` | server key principal | server only | reads `ca-cert.der`, `server-cert.der` | read-only verification |
| `LoadServingCandidate` | server key principal | server only | reads `ca-cert.der`, `server-cert.der`, `server-cert.pending.der` | read-only verification |
| `ConfirmServingCandidate` | server key principal **and** filesystem rights | server only | reads all four files; writes `server-cert.prev.der` via temporary + rename; renames `server-cert.pending.der` over `server-cert.der`; on a retry after promotion may delete `server-cert.pending.der` | read-only verification |
| `AbandonServingCandidate` | filesystem rights only | none | reads `server-cert.der`, `server-cert.pending.der`; deletes `server-cert.pending.der` | not touched |
| `CleanupMachine`, `CleanupMachineBySHA256` | privileged | CA + server deleted by exact name | deletes the whole directory | removes the exact anchor |

No serving or candidate path opens the CA key. Errors are not ordered by
privilege: `ReloadMachine` reads the CA DER before it opens the CA key, and
`StageServerRenewal` validates the CA, checks trust and reads the persisted
leaf before it opens the CA key. A non-privileged caller may therefore get a
file, validation or trust error first; `ErrPrivilegeRequired` is guaranteed
only when the CA key open is reached, and that open is denied before any native
key handle is obtained. `ErrPrivilegeRequired` from a key open comes from the
`windowscng` check of the calling thread's token; `MigrateMachineKeyPolicies`
and the first-install pre-check use Local TLS's own check of the process
token. Both fail closed, but they can differ under impersonation.

### Filesystem access

Local TLS does **not** set or verify ACLs on the TLS state directory or its
files. The `0700` / `0600` permission bits passed to the Go file APIs are not a
Windows ACL specification: on Windows they do not restrict which principals can
read, write, rename or delete the files. The resulting files inherit the ACL of
`%ProgramData%\Keppin\Agent\tls` and its parents.

**Owner: the installer/updater** (caller responsibility). It must create or
re-permission the directory so that each principal has the rights its
operations need and no more:

| Principal role | Needs on `...\Agent\tls` |
| --- | --- |
| serving (`LoadServingMaterial`, `LoadServingCandidate`) | read `ca-cert.der`, `server-cert.der`, `server-cert.pending.der` |
| renewal authority (`StageServerRenewal`) | read the DER files; create, write, rename (replace) and delete `server-cert.pending.der` and `.localtls-tmp-*` temporaries; list the directory |
| consumer `ConfirmServingCandidate` | read all four files; create, write and rename `.localtls-tmp-*` over `server-cert.prev.der` (replace); rename `server-cert.pending.der` over `server-cert.der` (replace, which also needs delete on the replaced file); delete `server-cert.pending.der` |
| consumer `AbandonServingCandidate` | read `server-cert.der` and `server-cert.pending.der`; delete `server-cert.pending.der` |
| administrative (provision, migration, cleanup) | full control of the directory |

Security notes for the deployment:

- Write access to the TLS state is **not** the authority to issue
  certificates (that requires the CA key), but it is not harmless: it allows
  altering or deleting state (availability) and replaying older public material
  that still validates. Grant it only to the principals that need it.
- `ca-cert.der` must be modifiable only by administrative principals. Note that
  rights granted at directory level for Confirm (replace/delete of children)
  can also allow replacing other files in the same directory; the deployment
  must evaluate the ACL layout it chooses. Local TLS does not prescribe one.
- Protect the directory path itself against replacement (for example of a
  parent directory) by unauthorized principals.
- All files, temporaries, pending and backup must stay in that one directory
  on a local NTFS volume (see
  [Writes, interruption and power loss](#writes-interruption-and-power-loss)).

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
```

- Mutating operations (`TrustProvisioner`) are elevated concerns. Within this
  module they are used only by first install and cleanup; no load, reload,
  renewal or existing-state provisioning path installs trust (policy).
  Read-only verification (`TrustVerifier`) is safe for normal runtime.
- `TrustStore` is a backward-compatibility combined interface; `EnsureTrusted` is
  **deprecated**. New code should use `TrustProvisioner` and `TrustVerifier`
  separately.
- `ComputeSHA256Fingerprint` returns the SHA-256 identity of a DER certificate.
- `ParseSHA256Fingerprint` parses a 64-hex-character fingerprint (surrounding
  whitespace tolerated, case-insensitive) into a `[32]byte`.

### Lower-level seam and testing APIs

```go
func ProvisionWithKeyStore(dataDir string, keyStore MachineKeyStore, trustStore TrustStore, now func() time.Time) (Material, error)
```

- `ProvisionWithKeyStore` is the key-store-based provisioning seam used by
  `ProvisionMachine`. It is exported but is a lower-level seam, not the preferred
  consumer entry point: it does **not** perform the first-install pre-check or
  privilege check that `ProvisionMachine` adds, and the single-writer contract
  applies to it as well.

The package also exports Windows-only test/smoke helpers (`TestCreateKey`,
`TestOpenKey`, `TestDeleteKey`, `TestSignAndVerify`, `ProvisionSmoke`,
`CleanupSmoke`, `VerifySmokeTrust`, `CleanupSmokeAnchorBySHA256`,
`SmokeCAKeyName`, `SmokeServerKeyName`) scoped to the `Keppin.Test.*` namespace.
These are testing surfaces, not production APIs; see
[Smoke helpers](#smoke-helpers). They still use the policy-free `windowscng`
API, which creates **every** test key with the service-signer DACL (LOCAL
SERVICE included) and accepts only that form. They therefore do
**not** follow the production key access policies: a smoke CA key is not
privileged-only, as the source comment of `TestCreateKey` also states.
Their name prefix check keeps them away from the production key names.

## Provisioning flow

`ProvisionMachine()` (Windows-only, elevated) performs **first install** or
**read-only verification of existing state**. It never repairs.

**First install** is entered only when neither certificate DER is present. A
conservative pre-check runs first and fails closed (policy) when:

- the server DER exists without the CA DER;
- the CA key opens although the CA DER is missing;
- the CA key open fails with any error other than `ErrKeyNotFound`;
- the caller is not LocalSystem or an elevated Administrator, or its privilege
  cannot be determined;
- the presence of a DER cannot be determined (for example access denied).

It then:

1. creates or opens the persisted CA and server CNG keys;
2. creates and persists public CA and server certificate DER only;
3. installs the exact local CA into `LocalMachine\Root` (idempotent).

The first-install server certificate becomes the persisted certificate without
consumer confirmation, because no previous certificate or consumer exists yet.

**Existing, complete state** is verified with the common validator (keys,
issuer, SANs, EKU, CA and leaf validity, leaf not outliving the CA, chain,
`TrustHealthy`). It **writes no DER, installs no trust and does not renew**
(policy). Success means "the existing state was verified", not "the certificate
was renewed": a still-valid leaf inside `RenewalThreshold` is returned with a
`nil` error; an expired leaf fails with `ErrRenewalDue` and
`ErrCertificateNotValidNow`.

- **No trust repair.** A `TrustAbsent` or `TrustConflict` anchor fails closed
  with `ErrTrustNotHealthy`; re-running `ProvisionMachine` does not reinstall a
  missing anchor (policy; verified). See
  [Trust states and recovery](#trust-states-and-recovery).
- **No partial-state repair.** Exactly one certificate DER present, or a DER
  whose presence cannot be determined, fails closed with
  `ErrInconsistentMachineState`. The CA certificate is never reissued for
  existing state, and keys are never regenerated (policy; verified).
- **Key acquisition on existing state.** Existing-state verification still
  acquires keys through the `MachineKeyStore` open-or-create seam, so "writes no
  DER" does not mean "never creates a key": a missing key name can be created as
  a side effect, after which verification fails on the key mismatch. The runtime
  and renewal paths open existing keys only.

**First-install limits (residual risk, accepted under the single-writer
contract):** the pre-check is a conservative gate, not proof that the CA key is
absent — `ErrKeyNotFound` means "not found or not accessible" even for
LocalSystem and Administrators. The check and the later open-or-create are not
atomic, so there is no guarantee that the CA key certified on first install was
created by that call. A first install interrupted after the DER writes but
before trust installation leaves complete DER with `TrustAbsent`, which a later
`ProvisionMachine` does not repair.

`LoadServingMaterial()` is the preferred serving-startup path:

- loads CA and server public DER (never a staged candidate);
- opens **only the server CNG key** (never the CA key);
- verifies server cert ↔ server key, issuer, SANs and server-auth EKU;
- verifies CA and server validity **now**, that the server certificate does not
  outlive the CA, and chain verification to the CA — an expired certificate fails
  closed with `ErrCertificateNotValidNow`;
- performs read-only trust verification and fails closed with
  `ErrTrustNotHealthy` unless the CA is `TrustHealthy`;
- never renews, never writes, and never mutates `LocalMachine\Root`.

`ReloadMachine()` is the **administrative** full-state verification path:

- **requires a privileged caller** (LocalSystem or elevated Administrators),
  because it opens the privileged-only CA key to prove that it matches the CA
  certificate. When it reaches the CA key open, a non-privileged caller gets
  `ErrPrivilegeRequired` without a key handle being obtained, and a CA key that
  still has the legacy DACL gets `ErrKeyPolicyMismatch` until
  `MigrateMachineKeyPolicies` has run. Earlier errors (CA DER missing or
  unreadable) are returned first;
- opens **both** the CA and server keys (open-only, never creates);
- applies the same certificate, validity and trust checks;
- never writes and never mutates `LocalMachine\Root`;
- does **not** renew: when the server certificate is within `RenewalThreshold`
  of expiry (or expired) it releases every handle and returns `ErrRenewalDue`
  (an expired certificate also matches `ErrCertificateNotValidNow`). CA, key,
  identity and trust failures detected first are returned with their own errors.

**`ReloadMachine` and `LoadServingMaterial` are not interchangeable.** The
separation already exists in the API; v0.3.0 adds no `ReloadServing` alias and
does not reduce `ReloadMachine` to a check that skips the CA key:

| | `ReloadMachine` | `LoadServingMaterial` |
| --- | --- | --- |
| Purpose | administrative verification of the complete machine state | load or reload the material for the HTTPS listener |
| Caller | privileged | server key principal (e.g. LOCAL SERVICE) |
| CA key | opened and matched against the CA certificate | never opened |
| Leaf inside `RenewalThreshold`, still valid | fails with `ErrRenewalDue` | returns the material (`nil` error) |
| Expired leaf | `ErrRenewalDue` + `ErrCertificateNotValidNow` | `ErrCertificateNotValidNow` |

A non-privileged runtime that called `ReloadMachine` in v0.2.x must switch to
`LoadServingMaterial` and must **not** be elevated to keep calling
`ReloadMachine`. Because `LoadServingMaterial` does not report `ErrRenewalDue`,
the consumer must decide separately when to start the staged renewal (for
example from `ServerCertificate.NotAfter` and `RenewalThreshold`, or by a
privileged `StageServerRenewal`, which returns `RenewalNotDue` when nothing is
due).

### Decision guide

| Need | Preferred API | Caller / mutation |
| --- | --- | --- |
| First install | `ProvisionMachine()` | Privileged; creates keys, writes DER, installs trust |
| Verify existing state (installer) | `ProvisionMachine()` | Privileged; writes nothing; never repairs trust or renews |
| Normal serving startup or reload | `LoadServingMaterial()` | Server key principal (e.g. LOCAL SERVICE); opens server key only; never writes; no trust mutation |
| Full-state verification | `ReloadMachine()` | Privileged (CA key); opens CA + server keys; never writes; reports `ErrRenewalDue`; no trust mutation |
| Server-certificate renewal | `StageServerRenewal()` (privileged) → `LoadServingCandidate(ref)` (server key principal) → consumer activation/attestation → `ConfirmServingCandidate(ref)` (server key principal + filesystem rights) or `AbandonServingCandidate(ref)` (filesystem rights) | No trust mutation; opens existing keys only; writes public DER only |
| Tighten legacy key ACLs | `MigrateMachineKeyPolicies()` | Privileged; rewrites the CA key DACL in place (tighten-only, idempotent); never rotates keys, writes DER or touches trust |
| Exact cleanup (DER available) | `CleanupMachine()` | Privileged; destructive |
| Cleanup by fingerprint | `CleanupMachineBySHA256(fp)` | Privileged; destructive |

## Server-certificate renewal

Renewal keeps the CA key, the server key, the CA certificate and the trust
anchor unchanged. Only a new public leaf is issued, and the persisted
certificate is replaced only when the consumer requests it.

| # | Event | Owner | API | Caller |
| --- | --- | --- | --- | --- |
| 1 | Stage a validated candidate | Local TLS | `StageServerRenewal()` | privileged (renewal authority) |
| 2 | Load exactly that candidate | Local TLS | `LoadServingCandidate(ref)` | server key principal |
| 3 | Activate it in the listener | consumer | consumer code | consumer |
| 4 | Attest that the listener serves it | consumer | consumer code | consumer |
| 5 | Promote it to the persisted certificate | Local TLS, on request | `ConfirmServingCandidate(ref)` | server key principal + filesystem rights |
| — | Discard the candidate | consumer request | `AbandonServingCandidate(ref)` | filesystem rights |

**Owner of the renewal coordination: the consumer (Keppin Agent)** (caller
responsibility). Steps 1 and 2–5 may run in different processes and under
different identities (for example step 1 as LocalSystem, steps 2–5 as LOCAL
SERVICE). One coordinator must still serialize the whole attempt — Stage →
Load candidate → listener activation → attestation by a real, non-resumed TLS
handshake → Confirm or Abandon — and must exclude concurrent key-ACL migration,
provisioning and cleanup for its duration. Staging is renewal authority; the
consumer steps never acquire CA authority.

- `StageServerRenewal` verifies the CA (validity, key match, `TrustHealthy`) and
  the identity of the persisted leaf; an expired previous leaf is accepted as the
  renewal base. It returns `RenewalNotDue` (nothing written) or
  `RenewalCandidateStaged`. It reuses a pending candidate only if it is valid now
  and advances the persisted certificate, and otherwise replaces it. It opens
  existing keys only, never installs trust, and never rotates keys or the CA.
  It requires a privileged caller and a migrated CA key (`ErrPrivilegeRequired`
  / `ErrKeyPolicyMismatch` when it reaches the CA key open; CA validity, trust
  and persisted-leaf errors can be returned first).
- `CandidateRef` carries the candidate, base and CA SHA-256 digests. It is public
  metadata only: **not** a secret, an authorization, a compare-and-swap token, or
  proof of activation. Keep it for the whole attempt; if it is lost, restart the
  attempt. The presence of a pending file never means "confirmed".
- `LoadServingCandidate` reverifies the CA and base digests and that the pending
  file is exactly `ref`'s candidate, applies the same checks as
  `LoadServingMaterial`, opens only the server key and never writes. Loading is
  **not** activation; the caller owns and must `Close` the returned `Material`.
- **Activation and attestation belong to the consumer** (caller responsibility).
  A suitable attestation is a fresh, full (non-resumed) handshake to the intended
  endpoint, verifying chain and name against the local CA and comparing the
  SHA-256 of the observed peer leaf with `ref.CandidateSHA256`. Keep the previous
  `Material` open until rollback is no longer possible.
- `ConfirmServingCandidate` is a **promotion request** after the consumer's own
  attestation, not proof of it: Local TLS cannot observe the listener. It
  revalidates CA, trust, candidate and digests, writes `server-cert.prev.der` as
  a copy of the current persisted certificate, then replaces `server-cert.der`
  with the candidate in one same-directory rename. It **opens the server key**
  to revalidate the candidate against it, so its caller needs both server key
  access and the filesystem rights in [Filesystem access](#filesystem-access).
  It never opens the CA key.
- `AbandonServingCandidate` deletes the pending file only when it is `ref`'s
  candidate. It is an idempotent no-op when nothing is pending (not proof of a
  rollback), returns `ErrCandidateMismatch` when a different candidate is pending
  and `ErrCandidatePromoted` when the candidate is already persisted. It never
  reverses a listener activation or a completed promotion.

Consumer rollback before promotion: restore the previous `Material` in the
listener, verify the restore, then call `AbandonServingCandidate`.

Consumer obligations during an attempt (caller responsibility):

- `CandidateRef` is not a lock and not an authorization; holding it does not
  reserve the state against other writers.
- `ConfirmServingCandidate` does not prove that the listener switched, and
  `AbandonServingCandidate` does not restore the listener. Both outcomes are the
  consumer's to verify.
- On any error, do not assume the effect: `ErrPromotionUnconfirmed` means the
  promotion may have happened. Retry with the same `ref`; treat `ErrCandidateStale`
  and `ErrCandidateMismatch` as "this attempt is over" and start a new attempt
  from `StageServerRenewal` rather than reusing the old `ref`.
- Keep the previous `Material` open until rollback is no longer possible, and
  `Close` each `Material` only when no handshake can use it any longer (see
  [Lifecycle & ownership of `Material`](#lifecycle--ownership-of-material)).

Retry and reconciliation (under the single-writer contract):

| State found by `ConfirmServingCandidate(ref)` | Result |
| --- | --- |
| persisted = base, pending = candidate | back up, then promote |
| persisted = candidate (completed, e.g. lost response) | revalidate; `nil` only while the promoted certificate still validates and no different pending exists; the backup is never rewritten |
| persisted = candidate, a different pending present | `ErrCandidateMismatch`; nothing touched |
| persisted ≠ base and ≠ candidate, or CA changed | `ErrCandidateStale`; nothing touched |
| pending missing / different | `ErrCandidateNotFound` / `ErrCandidateMismatch`; nothing touched |
| final rename reports an error | `ErrPromotionUnconfirmed`: the outcome is **unknown**, never "not promoted"; retry with the same `ref` |

**Post-promotion recovery is administrative**, not automatic: there is no
rollback API and no automatic fallback to the pending or backup file. Under the
single-writer contract, an administrator may revalidate `server-cert.prev.der`
(for example by restoring it and running `LoadServingMaterial`) and restore it
by writing a temporary file in the same directory and renaming it over
`server-cert.der`. If the backed-up predecessor has expired it cannot be served.
A missing or corrupt `server-cert.der` fails closed; nothing is regenerated.

### Writes, interruption and power loss

- **Write discipline (policy).** Every DER write goes through a temporary file in
  the same directory (reserved prefix `.localtls-tmp-`) that is written (a short
  write is an error), flushed and closed, then renamed with a single
  `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. Copy fallback
  is not allowed and the target is never deleted first. An error reported by the
  rename itself may come after it took effect; the caller reconciles. Orphan
  temporaries with the reserved prefix are removed only by `StageServerRenewal`.
  These paths are exercised by offline fault-injection and retry tests; there is
  no process-kill or power-cut test.
- **What is guaranteed after an interruption.** On a new load, bytes that fail
  DER, key, signature, SAN, EKU, time, chain or trust validation are rejected
  (policy; verified). That is the whole guarantee: older, authentic material that
  is still valid can pass validation.
- **What is not guaranteed.** Local TLS does **not** promise that the last
  confirmed promotion survives, monotonicity or anti-rollback, recoverability of
  the backup file, or availability after a sudden power loss. Durability across
  power loss depends on the filesystem, drivers and storage honouring flushes and
  write-through, and the backup-then-promote sequence is not one atomic
  transaction.
- **Assumptions.** The persisted keys and the trust anchor are retained, the
  system clock is correct, and the TLS directory, its temporaries and the
  pending/backup files are on one local NTFS volume in the same directory.
- **Sharing.** A reader that holds `server-cert.der` open can block the rename;
  `ConfirmServingCandidate` then returns `ErrPromotionUnconfirmed`. Retry with the
  same `ref`.

Local TLS does not ship a listener integration. The renewal protocol is exercised
in this repository's tests offline, with a fake in-memory consumer and an
in-memory TLS handshake.

## Certificate & key lifecycle

Verified properties of the generated material:

- CA and server keys are **ECDSA P-256**.
- CA certificate is **self-signed**: `IsCA`, `BasicConstraintsValid`,
  `MaxPathLen=0` (`MaxPathLenZero=true`), key usage restricted to
  `KeyUsageCertSign` only (no `CRLSign`, no `DigitalSignature`).
- Server certificate is signed by that CA; server-auth EKU only.
- Server identity is strictly local: DNS SAN `localhost`; IP SANs `127.0.0.1`
  and `::1` (validated by `validateSAN`).
- CA validity is 5 × 365 days and server validity is 90 days, each starting
  5 minutes before issuance. Renewal is due when the server certificate is within
  `RenewalThreshold` (**30 days**) of expiry or already expired.
- Renewal **reuses** the existing persisted server key — key rotation is
  decoupled from certificate renewal (verified).
- The CA `MaxPathLen=0` constraint rejects subordinate-CA chains (verified by
  `TestSubordinateCAChainRejected`).

Validity rules (policy; verified):

- **Inclusive validity.** A CA or server certificate is valid at exactly its
  encoded `NotBefore` and exactly its encoded `NotAfter` instant, consistent with
  Go `crypto/x509`; one nanosecond outside either bound is invalid
  (`ErrCertificateNotValidNow`).
- **Leaf never outlives the CA.** A server certificate whose `NotAfter` is after
  the CA's `NotAfter` is rejected with `ErrLeafOutlivesCA`. Local TLS never
  shortens ("caps") a leaf to fit and never renews or rotates the CA
  automatically.
- **Conservative staging fit.** `StageServerRenewal` refuses with
  `ErrLeafOutlivesCA` when `now + 90 days` is after the CA's `NotAfter`. This is
  checked on the requested validity before encoding, so it is stricter than the
  validation rule above (a sub-second difference that encoding would round away
  is still refused). Consequence: during roughly the last 90 days of the CA's
  life no renewal can be staged; replacing the CA requires cleanup and fresh
  provisioning, which creates a new CA fingerprint.

Key custody:

- The module never receives private-key bytes — it operates on `crypto.Signer`
  handles only, and persists only the public certificate DER (policy; verified by
  construction).
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
  - `TrustHealthy` — exact CA present (other same-subject anchors are not
    examined in that case);
  - `TrustConflict` — same-subject certificate with a different fingerprint
    (manual resolution required; never auto-remove);
  - `TrustAbsent` — CA not present;
  - `TrustError` — verification itself failed.
- `IsTrustedSHA256` reports exact-fingerprint presence.

Trust verification uses exact CA identity, not loose subject-name trust. A
conflicting certificate (same CN, different fingerprint) is reported as
`TrustConflict` (verified).

### Trust states and recovery

Every load, reload, renewal and existing-state provisioning path requires
`TrustHealthy` and otherwise fails closed with `ErrTrustNotHealthy`. None of
them installs or repairs trust (policy; verified).

| State | Response |
| --- | --- |
| `TrustHealthy` | none |
| `TrustAbsent` | fails closed everywhere; **no automatic or API-based repair** (see below) |
| `TrustConflict` | manual resolution required; never auto-remove the conflicting anchor |
| `TrustError` | inspect trust-store access; retry the read-only verification |

No provisioning call repairs trust. Match `ErrTrustNotHealthy` with `errors.Is`
and do not rely on the message text.

Recovering from `TrustAbsent` on otherwise complete state is an operator
decision outside the Local TLS API. Neither option below is automatic, and
neither is guaranteed to restore service:

- **Operator-managed import of the exact persisted CA.** An operator may import
  the exact persisted `ca-cert.der` into `LocalMachine\Root` with their own
  tooling. Local TLS does not perform, support or validate this import; it only
  verifies the resulting trust state on the next load, by exact fingerprint.
  Importing any other certificate does not make the state `TrustHealthy`.
- **Cleanup and fresh provisioning.** `CleanupMachine` followed by a new
  `ProvisionMachine` first install creates a **new CA key and a new CA
  fingerprint**. Consumers that pin or distributed the old CA certificate or
  fingerprint stop trusting the new material. A fresh first install happens only
  after a cleanup that returned `nil`; while cleanup retains the state directory
  (see below), `ProvisionMachine` keeps failing closed.

## Cleanup behavior

`CleanupMachine()` and `CleanupMachineBySHA256(fp)` remove, in order, on a
best-effort basis across independently removable artifacts:

1. the exact local CA trust anchor from `LocalMachine\Root`;
2. the exact local CA CNG key;
3. the exact local server CNG key;
4. the Local TLS state directory (`...\Agent\tls`), including the pending and
   backup files.

Failure semantics:

- a failure on one artifact does not stop removal of the others (best-effort);
- failures not attributable to "already absent" are aggregated with `errors.Join`
  so no security-sensitive artifact failure is silently swallowed (verified);
- an already-absent trust anchor (`ErrTrustAnchorNotFound`) or state directory
  is idempotent success;
- a key delete that reports `ErrKeyNotFound` (not found **or not accessible**)
  is **not** a confirmed deletion: it is returned as `ErrKeyDeletionUnconfirmed`
  (which also matches `ErrKeyNotFound`), and the state directory, including the
  CA DER, is then retained for diagnosis and a retried cleanup (verified).
  Cleanup returns `nil` only when both key deletions were confirmed, so a
  repeated cleanup reports an unconfirmed deletion;
- cleanup never deletes by subject/CN, wildcard, prefix, or unrelated parent
  directory.

`CleanupMachine` needs the on-disk CA DER to identify the trust anchor. If the
state directory (and thus the DER) is already gone, use
`CleanupMachineBySHA256` with the known fingerprint. Cleanup removes only the
anchor identified by that DER or fingerprint; it does not search for other
historical anchors.

### Smoke helpers

`ProvisionSmoke` and `CleanupSmoke` operate on a caller-chosen test root and the
`Keppin.Test.Smoke.*` key names only; they require Administrator elevation.
`CleanupSmoke` follows the same contract as production cleanup:

- **An error does not mean nothing was cleaned up.** When both smoke key
  deletions are confirmed, removal of the smoke root is attempted even if
  trust-anchor removal failed; the trust error is still returned with the root
  (and its CA DER) gone. Preserve the exact CA DER or its fingerprint outside the
  smoke root if trust removal may need a retry; the fingerprint works with
  `CleanupSmokeAnchorBySHA256`.
- **A retry may never return nil.** An ambiguous `ErrKeyNotFound` keeps
  producing `ErrKeyDeletionUnconfirmed` and the root is retained; do not treat
  that as a confirmed deletion.

## Error semantics

- When provisioning, loading or reloading fails, the returned `Material` is zero
  and every handle the module opened has been released.
- `ProvisionMachine` returns `ErrInconsistentMachineState` for partial or
  incoherent state. When complete DER exists but a persisted key cannot be
  opened, the error **also** matches `ErrKeyNotFound` (several causes may be
  joined). Check `ErrInconsistentMachineState` first, and never treat a nested
  `ErrKeyNotFound` as permission to initialize, reset or delete anything
  (caller responsibility).
- `ErrRenewalDue`: `ReloadMachine` reports it as soon as the leaf is within
  `RenewalThreshold` of expiry; existing-state provisioning reports it only once
  the leaf has expired. Run the staged renewal flow.
- `ErrCertificateNotValidNow`, `ErrLeafOutlivesCA` and `ErrTrustNotHealthy` are
  fail-closed results of the common validator.
- Renewal sentinels (`ErrNoCandidate`, `ErrCandidateNotFound`,
  `ErrCandidateMismatch`, `ErrCandidateStale`, `ErrCandidatePromoted`,
  `ErrPromotionUnconfirmed`) are described in
  [Server-certificate renewal](#server-certificate-renewal).
- In cleanup only `ErrTrustAnchorNotFound` is idempotent success;
  `ErrKeyNotFound` is reported as `ErrKeyDeletionUnconfirmed`.
- `ErrPrivilegeRequired`: the caller's token is not privileged, or its
  privilege could not be determined. It is not guaranteed to be the first error
  a non-privileged caller sees (see
  [Privilege and access matrix](#privilege-and-access-matrix)). Do not respond
  by elevating a serving runtime; use the serving APIs instead.
- `ErrKeyPolicyMismatch`: the key DACL is not exactly its role policy. On a CA
  key this usually means the key-ACL migration has not run; any other DACL needs
  administrative inspection. The key is never modified as a side effect.

## Security model

- Private keys are machine-scoped CNG keys and never persisted as files; the
  module never handles private-key bytes.
- The CA key is privileged-only on a v0.3.0 first install and after
  `MigrateMachineKeyPolicies`: no LOCAL SERVICE process can then open it or
  sign with it, and only the server key is usable by the non-privileged
  runtime. **Before** the migration a legacy CA key stays open to every LOCAL
  SERVICE process, whatever library version is installed (see
  [Key access policies](#key-access-policies)).
- The server signing key is shared by every LOCAL SERVICE process on the
  machine; Local TLS does not isolate the Agent from them.
- Local TLS does not enforce filesystem ACLs on the TLS state; their
  correctness is a deployment responsibility (see
  [Filesystem access](#filesystem-access)).
- The CA is a path-length-zero, sign-only CA used exclusively to issue the local
  `localhost` server certificate.
- Trust is anchored on exact SHA-256 identity, not subject name.
- Missing or conflicting trust, cert/key mismatch, unexpected issuer, invalid
  SAN or EKU, invalid validity, and a leaf outliving the CA all fail closed.
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
- With `github.com/keppin-oss/cng v0.2.1`, the first `Close()` may return an
  error if a native handle cannot be released; the release is not retried, and
  repeated calls are harmless and return `nil`. The CNG signer serializes `Sign`
  and `Close`, but `Close()` does not drain callers: close a `Material` only
  when no handshake can use it any longer.
- `Material` is single-owner; do not copy it by value and reuse the copy after
  `Close`.

## Windows / platform behavior

- Production machine functions are Windows-only (`//go:build windows`).
- On non-Windows (`//go:build !windows`), the machine functions
  (`MachineAgentPath`, `MachineTLSPath`, `ProvisionMachine`, `ReloadMachine`,
  `LoadServingMaterial`, `StageServerRenewal`, `LoadServingCandidate`,
  `ConfirmServingCandidate`, `AbandonServingCandidate`, `CleanupMachine`,
  `CleanupMachineBySHA256`) and the platform seams (`PlatformKeyStore`,
  `PlatformKeyDeleter`, `PlatformTrustStore`) return explicit
  unsupported-platform errors. The smoke and test-key helpers exist only on
  Windows.
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
  `ProvisionMachine()` (first install or existing-state verification; no renewal
  or trust repair) and inspection of the returned public metadata. Mutates
  machine CNG state and `LocalMachine\Root` on first install; must not run in
  normal tests. Windows-only.
- [`examples/fingerprint`](../examples/fingerprint/main.go) — non-destructive
  demonstration of `ComputeSHA256Fingerprint`, `ParseSHA256Fingerprint`, and the
  `CleanupMachine` vs `CleanupMachineBySHA256` handoff decision. Cross-platform.

## Validation

Default validation path:

```text
go build ./...
go vet ./...
go test ./...
```

On non-Windows, the Windows-specific tests are excluded by build tags. On
Windows, `go test ./...` is **not** a safe, all-green suite:

- `TestCleanupLifecycleElevated` is skipped only when elevation is clearly
  unavailable. Under a UAC-filtered (non-elevated) Administrator token its
  elevation probe is ambiguous (the probe key cannot be finalized and its
  rollback delete reports "not found"), so the test fails closed and is reported
  as **FAIL**, not SKIP. This is a known result, not a v0.3.0 regression and
  not masked as a skip. Each such run attempts to create a
  `Keppin.Test.Smoke.elevation-probe-*` key.
- The trust-store tests `TestTrustStoreInstallAndVerify`,
  `TestTrustStoreConflictingCert` and `TestRemoveNonExistent` use
  `LocalMachine\Root` directly and are not elevation-gated;
  `TestTrustStoreEmptyDER` and `TestPlatformTrustStoreReturnsStore` open the
  real platform trust store.

The **safe suite** — non-privileged, without machine CNG lifecycle or
`LocalMachine\Root` access — excludes all six:

```text
go test ./... -skip '^(TestTrustStoreInstallAndVerify|TestTrustStoreConflictingCert|TestRemoveNonExistent|TestCleanupLifecycleElevated|TestTrustStoreEmptyDER|TestPlatformTrustStoreReturnsStore)$'
```

Report results of the safe suite and of the machine tests separately; do not
describe a run of the full suite as green.

Elevated Windows validation for the CNG / trust-store / cleanup lifecycle runs
from an elevated shell on a disposable Windows environment:

```text
go test -v ./... -run 'TestCleanupLifecycleElevated|TestTrustStore|TestRemoveNonExistent'
```

The renewal protocol, its fault injection and retries, and a fake consumer with
an in-memory TLS handshake run offline and unprivileged with `go test`. Live
flows requiring elevation, machine CNG state, and `LocalMachine\Root` mutation
are reported **NOT EXECUTED** in unprivileged environments and must be validated
manually on a disposable Windows environment.

The key access policies, the role separation and the key-ACL migration are
covered offline by fake-based and structural tests (`TestKeyPolicy*`,
`TestProductionKeyOperations*`, `TestAgentRole*`, `TestCARolePathsFailClosed`,
`TestLegacyServingCompatibleBeforeMigration`, `TestMigrateKeyPolicies*`,
`TestProductionCodeAvoidsLegacyPolicyFreeCNG`), which touch no real key, ACL or
trust store.

### Windows validation of the key policies

The v0.3.0 key policies were validated once on a disposable Windows 11 VM with
real tokens (elevated Administrator, UAC-filtered Administrator, LocalSystem
and a real LOCAL SERVICE token obtained through a temporary scheduled task) and
the real Microsoft Software KSP, using test-only key names and a test state
directory. Observed: CA privileged-only and server service-signer DACLs on a
fresh install; LOCAL SERVICE serves and signs with the server key and cannot
open the CA key; `ReloadMachine`, `StageServerRenewal` and the migration are
denied to non-privileged callers; a legacy DACL is recognized and migrated
tighten-only and idempotently, with key names, public keys, certificate DER and
CA fingerprint unchanged; negative cases fail closed; the staged renewal
completes end to end with a real non-resumed handshake; cleanup restores the
baseline. The harness is not part of this repository.

Limits of that validation (accepted or to be closed before a release is
declared validated):

- The exported wrappers (`ProvisionMachine`, `LoadServingMaterial`,
  `MigrateMachineKeyPolicies`, …) were **not** called directly, because they
  are bound to the production key names and `%ProgramData%\Keppin`; the harness
  ran the same internal bodies with test names and paths. Production names,
  paths and deployment ACLs were therefore not exercised.
- The legacy state was reproduced with the legacy `windowscng` API, not by an
  installation made with a released v0.2.x binary; no real v0.2.x → v0.3.0
  upgrade or v0.3.0 → v0.2.x downgrade was run.
- Renewal timing was injected rather than waited for; LOCAL SERVICE came from
  a scheduled task, not a Service Control Manager service.
- The test helpers keep their legacy DACL (see
  [Lower-level seam and testing APIs](#lower-level-seam-and-testing-apis)).
- Test and production CAs share the CN `Keppin Local Root CA`: a leftover test
  anchor in `LocalMachine\Root` makes `VerifyTrust` report `TrustConflict` for
  another CA with the same CN. Clean up test anchors by exact fingerprint.
- `TestCleanupLifecycleElevated` remains a known FAIL under a UAC-filtered token
  (see above).

## Limitations

- **Windows-only** for production machine flows.
- **Microsoft Software KSP only** — no other key provider is supported.
- **No trust repair** — a missing trust anchor on existing state is never
  reinstalled by the module.
- **No CA renewal or rotation** — replacing the CA means cleanup and fresh
  provisioning with a new fingerprint.
- **No listener integration** — activation and attestation of a renewed
  certificate are consumer code.
- Trust-conflict resolution is **manual** — the module never auto-removes a
  conflicting anchor.
- The single-writer contract is not enforced by the module.
- **No per-service key isolation** — the server key is usable by every LOCAL
  SERVICE process, not only by the Agent.
- **No filesystem ACL enforcement** — the TLS state directory ACLs are set by
  the installer/updater.
- **No implicit key-ACL migration** — a legacy CA key stays exposed to LOCAL
  SERVICE until `MigrateMachineKeyPolicies` is run explicitly.
- **Existing-state provisioning uses open-or-create** — acceptable only under
  the single-writer contract; the open-only probe before it is not an atomic
  guarantee.
- The module does not provide a generic TLS/PKI or trust-store framework.

## Troubleshooting

1. **Platform** — is this Windows? On non-Windows the machine functions return
   explicit unsupported-platform errors.
2. **Provisioning** — was `ProvisionMachine()` already run (elevated)? Serving
   startup requires previously persisted machine material.
3. **Privilege** — provisioning, `ReloadMachine`, staging, migration and
   cleanup require LocalSystem or an elevated Administrator
   (`ErrPrivilegeRequired`). Serving does not, but the process token must be
   authorized by the server key DACL: LOCAL SERVICE is, a UAC-filtered
   Administrator is not.
4. **Key policy** — `ErrKeyPolicyMismatch` on the CA key after an upgrade from
   v0.2.x means the key-ACL migration has not run; see
   [Upgrading from v0.2.x to v0.3.0](#upgrading-from-v02x-to-v030). On any other
   key or DACL, inspect manually; never widen a DACL to make an open succeed.
5. **Trust** — `TrustAbsent` / `TrustConflict` fails closed with
   `ErrTrustNotHealthy`; re-running `ProvisionMachine` does not repair it. See
   [Trust states and recovery](#trust-states-and-recovery). Do not weaken trust
   checks and do not auto-remove a conflicting anchor.
6. **Inconsistent state** — `ErrInconsistentMachineState` is never resolved
   automatically; inspect the state directory and keys before any cleanup.
7. **Renewal** — `ErrRenewalDue` means "run the staged renewal flow". A
   successful `ProvisionMachine` does not mean the certificate was renewed. An
   expired certificate fails closed in `LoadServingMaterial` until a candidate is
   staged, activated, attested and confirmed.
8. **Sentinels** — match with `errors.Is`, never on message text.

## Upgrading from v0.2.x to v0.3.0

v0.3.0 is a **breaking** release. Under SemVer pre-1.0 (`0.y.z`) a breaking
change is carried by a minor version, so the module path and major version are
unchanged; v0.3.0 must not be treated as a drop-in patch of v0.2.x. The
persisted identities (key names, directory and file names) are unchanged.
Code that compiled against v0.2.x still compiles, but compiling is **not**
evidence of operational compatibility: the privilege contract, the consumer
call sites and the upgrade procedure change. v0.3.0 has no legacy mode and no
compatibility switch.

### Behavior changes

| Area | v0.2.x | v0.3.0 |
| --- | --- | --- |
| CA key DACL | service-signer (LOCAL SERVICE read/execute) | privileged-only (`PolicyPrivilegedOnly`) on first install; legacy keys only after `MigrateMachineKeyPolicies` |
| Server key DACL | service-signer | unchanged (`PolicyServiceSigner`), now verified exactly on every open |
| Key opens | policy-free `windowscng` API | policy-aware `windowscng` API; a DACL other than the role policy fails with `ErrKeyPolicyMismatch` |
| `ReloadMachine` | no elevation required; any principal authorized by the legacy DACL, LOCAL SERVICE included | **privileged only**; administrative full-state verification |
| `StageServerRenewal` | no elevation required; any principal authorized by the legacy DACL, LOCAL SERVICE included | **privileged only** (renewal authority) |
| `ProvisionMachine` on existing state | opened the keys under the legacy DACL | fails with `ErrKeyPolicyMismatch` on a legacy CA key until migrated |
| `LoadServingMaterial`, `LoadServingCandidate` | opened the server key under the legacy DACL | unchanged for a server key principal; work on legacy installations before migration |
| `ConfirmServingCandidate`, `AbandonServingCandidate` | preconditions not documented | unchanged; their caller and filesystem preconditions are now documented |
| New API | — | `MigrateMachineKeyPolicies()`; sentinels `ErrKeyPolicyMismatch`, `ErrPrivilegeRequired` |
| CNG dependency | `github.com/keppin-oss/cng v0.2.0` | `v0.2.1` (policy-aware API now used; `Sign`/`Close` synchronized; the first `Close` may report a handle-release error) |

### Migrating call sites

- **Non-privileged `ReloadMachine` callers** (for example the Agent's listener
  reload) move to `LoadServingMaterial`. Do **not** elevate the runtime to keep
  calling `ReloadMachine`. `LoadServingMaterial` does not report
  `ErrRenewalDue`, so move renewal scheduling into separate consumer logic (see
  [`ReloadMachine` and `LoadServingMaterial` are not interchangeable](#provisioning-flow)).
- **`StageServerRenewal` callers** must run as LocalSystem or an elevated
  Administrator. The consumer steps (`LoadServingCandidate`, activation,
  attestation, `ConfirmServingCandidate` / `AbandonServingCandidate`) may stay
  in the LOCAL SERVICE runtime, coordinated as described in
  [Server-certificate renewal](#server-certificate-renewal).
- **Error handling** adds `ErrPrivilegeRequired` and `ErrKeyPolicyMismatch`
  (match with `errors.Is`). Neither is a reason to elevate a serving runtime,
  widen a DACL, regenerate a key or clean up.
- **Deployment** sets the TLS state directory ACLs described in
  [Filesystem access](#filesystem-access); Local TLS does not.
- Verify every consumer against this matrix before adopting v0.3.0.

### Migrating key access policies

Installations provisioned before v0.3.0 have a CA key whose DACL grants LOCAL
SERVICE read/execute. **Installing the v0.3.0 library alone does not remove
that exposure**: until the migration succeeds, any LOCAL SERVICE process can
still open the CA key through the native CNG API. Do not declare an
installation protected because the library was upgraded.

**Owner: the privileged installer/updater**, as one serialized administrative
upgrade step. Local TLS never migrates implicitly, and serving never runs the
migration. Cutover procedure:

1. Stop every process that uses Local TLS on the machine (the old Agent and any
   older binary that may hold a CA key handle) and make sure no provisioning,
   renewal attempt or cleanup is in progress. Rewriting the DACL denies new
   opens; it is **not** assumed to revoke handles already open, so old
   processes must have exited before the migration counts as effective.
2. Deploy the v0.3.0 binaries.
3. As LocalSystem or an elevated Administrator, call
   `MigrateMachineKeyPolicies()` once:

   ```go
   if err := localtls.MigrateMachineKeyPolicies(); err != nil {
      // fail closed: inspect the error; never regenerate keys or the CA,
      // never widen a DACL
   }
   ```

4. Optionally confirm the result with a privileged `ReloadMachine()` (it reports
   `ErrRenewalDue` if a renewal is due).
5. Restart the services and resume the normal lifecycle: serving through
   `LoadServingMaterial`, renewal through the staged flow.

`MigrateMachineKeyPolicies`:

- requires LocalSystem or an elevated Administrators member
  (`ErrPrivilegeRequired`, no key touched) and complete provisioned state, both
  certificate DERs present (`ErrInconsistentMachineState`, no key touched);
- verifies read-only that the server key opens under `PolicyServiceSigner` and
  matches the server certificate; if not, the CA key is not touched; the server
  DACL is never rewritten;
- rewrites the CA key DACL in place from the exact service-signer form to
  privileged-only, with read-back on the open handle and on a fresh handle; a CA
  key that is already privileged-only is left untouched, so repeated runs are
  no-ops;
- verifies that the CA key opens under `PolicyPrivilegedOnly`, matches the CA
  certificate, and that the CA certificate DER is unchanged.

It never creates, regenerates, rotates or deletes a key, never writes a
certificate and never reads or modifies `LocalMachine\Root`; key names, public
keys, certificate DER and the CA fingerprint are preserved. Any other DACL fails
closed with `ErrKeyPolicyMismatch` without a write; `ErrKeyNotFound` is reported
as a failure, never as absence, and nothing is created.

Failures and partial state:

- **Before the DACL write** (privilege, incomplete or unreadable state, server
  key check, unexpected CA DACL, CA key not opening): nothing has changed. Fix
  the cause and run the migration again.
- **After the DACL write** (read-back or final verification fails): the CA key
  may already be privileged-only while the migration reports an error. There is
  **no rollback**, because rolling back would widen access. Inspect
  administratively and re-run the migration, which is a no-op on an already
  tightened key and then repeats the verification. Never regenerate the CA or
  restore the legacy DACL.
- **Between deploy and migration** the installation is in a transitional state:
  serving works; `ProvisionMachine`, `ReloadMachine` and `StageServerRenewal`
  fail with `ErrKeyPolicyMismatch`; the CA key is still exposed. Keep this
  window inside the upgrade step and do not report the mitigation as complete
  during it.

Downgrade: the migration is never reverted, so the v0.2.x contract does not come
back with v0.2.x binaries. After migration, v0.2.x binaries can no longer open
the CA key (their policy-free open accepts only the service-signer DACL):
operations that need the CA, such as `ReloadMachine` and renewal, fail closed,
while serving with the unchanged server key is expected to keep working. This
behavior follows from the DACL check and has not been verified with a released
v0.2.x binary.

## Upgrading from v0.1.x

v0.2.0 is a breaking release. The persisted identities (key names, directory and
file names) are unchanged, so v0.2.0 reads machine state written by v0.1.x, but
several behaviors change on purpose. This repository does not include a test
that upgrades live v0.1.x machine state.

### Reliability notice for v0.1.x

v0.1.x has lifecycle behaviors that v0.2.0 replaces because they can leave a
machine in a state that is hard to diagnose or recover: in-place server
certificate renewal without consumer confirmation, cleanup that treated an
ambiguous "key not found or not accessible" result as a successful deletion,
re-issuing a CA certificate for partial state through the `ProvisionWithKeyStore`
seam, and silently shortening a leaf near CA expiry. This is a reliability and
migration notice; no exploitation or security incident is claimed. Users of
v0.1.x should plan the migration below.

### Behavior changes

| Area | v0.1.x | v0.2.0 |
| --- | --- | --- |
| `ProvisionMachine` on existing state with `TrustAbsent` | reinstalled the persisted CA into `LocalMachine\Root` | **fails closed** with `ErrTrustNotHealthy`; installs nothing, regenerates nothing, writes no DER, does not renew |
| `ProvisionMachine` on existing state, renewal window | renewed the server certificate in place | verifies only; returns a still-valid leaf with `nil`, an expired leaf with `ErrRenewalDue` |
| `ReloadMachine` | renewed the server certificate in place when due | never writes; returns `ErrRenewalDue` |
| Renewal | implicit, in place | explicit `StageServerRenewal` → `LoadServingCandidate` → consumer activation/attestation → `ConfirmServingCandidate` / `AbandonServingCandidate` |
| `LoadServingMaterial` | did not check expiry | fails closed on an expired or not-yet-valid certificate and on a leaf outliving the CA |
| Leaf near CA expiry | `NotAfter` capped at the CA's `NotAfter` | rejected with `ErrLeafOutlivesCA`; no capping |
| Validity boundary | CA treated as expired at exactly `NotAfter` | inclusive at `NotBefore` and `NotAfter` for CA and leaf |
| Partial state via `ProvisionWithKeyStore` | could re-issue a CA certificate when the CA DER was missing | fails closed with `ErrInconsistentMachineState` |
| Cleanup and `CleanupSmoke` on `ErrKeyNotFound` | idempotent success; smoke root always removed | `ErrKeyDeletionUnconfirmed`; state directory / smoke root retained |
| `ErrKeyNotFound` | "key not found" | "not found or not accessible"; never proof of absence |
| Legacy API | `Provision`, `Protector`, `PlatformProtector` exported | removed |
| CNG dependency | `github.com/keppin-oss/cng v0.1.2` | `v0.2.0` |

### Migration steps

- **Callers relying on implicit renewal** (`ReloadMachine` or re-running
  `ProvisionMachine`) compile unchanged but must handle `ErrRenewalDue` and
  implement the staged renewal flow, including activation and attestation in
  their listener.
- **Callers relying on trust repair** by re-running `ProvisionMachine` must
  handle `ErrTrustNotHealthy` as an operator decision; see
  [Trust states and recovery](#trust-states-and-recovery). Plan for the CA
  fingerprint change if cleanup and fresh provisioning are chosen.
- **Callers of `Provision` / `Protector`** must move to the machine/CNG entry
  points. There is no migration of previously exported legacy keys into CNG;
  such material must be retired and provisioned fresh.
- **Cleanup callers** must treat `ErrKeyDeletionUnconfirmed` as "not confirmed",
  keep the retained state for diagnosis, and must not expect a repeated cleanup
  to return `nil`.
- **Error handling** must use `errors.Is` with the sentinels above, giving
  `ErrInconsistentMachineState` precedence over a nested `ErrKeyNotFound`.
- **CA lifetime planning** — since the leaf is never capped and the CA is never
  renewed automatically, plan CA replacement (cleanup and fresh provisioning)
  before the last 90 days of the CA's validity.
