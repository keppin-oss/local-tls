# Local TLS — Technical Documentation

This is the technical reference for the `local-tls` module
(`github.com/keppin-oss/local-tls`, package `localtls`). It documents what the
module does, how it is structured, and — critically — the boundary of what is
guaranteed versus what is caller responsibility or best-effort.

Every claim in this document is traceable to the source, the tests, the build
tags, or `go.mod`. Where a behavior is not demonstrable from this repository, it
is labeled explicitly.

Upgrading from v0.1.x? Read [Upgrading from v0.1.x](#upgrading-from-v01x)
first: v0.2.0 contains intentional breaking behavior changes.

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
- **Administrator elevation** is required for `ProvisionMachine`, `CleanupMachine`,
  and `CleanupMachineBySHA256` (caller responsibility). On first install,
  `ProvisionMachine` itself fails closed for a caller that is not LocalSystem or
  an elevated Administrator, or whose privilege cannot be determined (policy).
  `LoadServingMaterial`, `LoadServingCandidate`, `ReloadMachine`, and read-only
  trust verification do not mutate machine trust and do not require elevation,
  but the calling process must be able to open the persisted key(s) they use
  (caller responsibility). The renewal steps that write (`StageServerRenewal`,
  `ConfirmServingCandidate`, `AbandonServingCandidate`) need write access to the
  TLS state directory; `StageServerRenewal` also opens the CA key.
- **Single lifecycle writer** (caller responsibility). One lifecycle coordinator
  per machine must ensure that provisioning, cleanup/uninstall, administrative
  recovery and every server-certificate renewal attempt (the whole sequence
  `StageServerRenewal` → `LoadServingCandidate` → consumer activation and
  attestation → `ConfirmServingCandidate` or `AbandonServingCandidate`) never
  overlap, and that no other actor creates, deletes or re-permissions the
  Local TLS key names or state directory while they run. Local TLS does **not**
  implement or verify this serialization. The digest checks of the renewal API
  detect some violations, not all; they are not a lock.
- **Microsoft Software Key Storage Provider** is the only supported key store.
- **Go** — the module declares `go 1.26.8`.

### Dependencies

```
github.com/keppin-oss/cng v0.2.0      // windowscng — CNG/KSP key custody
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
[Smoke helpers](#smoke-helpers).

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

`ReloadMachine()` is the full-state verification path:

- opens **both** the CA and server keys (open-only, never creates);
- applies the same certificate, validity and trust checks;
- never writes and never mutates `LocalMachine\Root`;
- does **not** renew: when the server certificate is within `RenewalThreshold`
  of expiry (or expired) it releases every handle and returns `ErrRenewalDue`
  (an expired certificate also matches `ErrCertificateNotValidNow`). CA, key,
  identity and trust failures detected first are returned with their own errors.

### Decision guide

| Need | Preferred API | Elevation / mutation |
| --- | --- | --- |
| First install | `ProvisionMachine()` | Administrator; creates keys, writes DER, installs trust |
| Verify existing state (installer) | `ProvisionMachine()` | Administrator; writes nothing; never repairs trust or renews |
| Normal serving startup | `LoadServingMaterial()` | No trust mutation; opens server key only; never writes |
| Full-state verification | `ReloadMachine()` | No trust mutation; opens CA + server keys; never writes; reports `ErrRenewalDue` |
| Server-certificate renewal | `StageServerRenewal()` → `LoadServingCandidate(ref)` → consumer activation/attestation → `ConfirmServingCandidate(ref)` or `AbandonServingCandidate(ref)` | No trust mutation; opens existing keys only; writes public DER only |
| Exact cleanup (DER available) | `CleanupMachine()` | Administrator; destructive |
| Cleanup by fingerprint | `CleanupMachineBySHA256(fp)` | Administrator; destructive |

## Server-certificate renewal

Renewal keeps the CA key, the server key, the CA certificate and the trust
anchor unchanged. Only a new public leaf is issued, and the persisted
certificate is replaced only when the consumer requests it.

| # | Event | Owner | API |
| --- | --- | --- | --- |
| 1 | Stage a validated candidate | Local TLS | `StageServerRenewal()` |
| 2 | Load exactly that candidate | Local TLS | `LoadServingCandidate(ref)` |
| 3 | Activate it in the listener | consumer | consumer code |
| 4 | Attest that the listener serves it | consumer | consumer code |
| 5 | Promote it to the persisted certificate | Local TLS, on request | `ConfirmServingCandidate(ref)` |
| — | Discard the candidate | consumer request | `AbandonServingCandidate(ref)` |

- `StageServerRenewal` verifies the CA (validity, key match, `TrustHealthy`) and
  the identity of the persisted leaf; an expired previous leaf is accepted as the
  renewal base. It returns `RenewalNotDue` (nothing written) or
  `RenewalCandidateStaged`. It reuses a pending candidate only if it is valid now
  and advances the persisted certificate, and otherwise replaces it. It opens
  existing keys only, never installs trust, and never rotates keys or the CA.
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
  with the candidate in one same-directory rename.
- `AbandonServingCandidate` deletes the pending file only when it is `ref`'s
  candidate. It is an idempotent no-op when nothing is pending (not proof of a
  rollback), returns `ErrCandidateMismatch` when a different candidate is pending
  and `ErrCandidatePromoted` when the candidate is already persisted. It never
  reverses a listener activation or a completed promotion.

Consumer rollback before promotion: restore the previous `Material` in the
listener, verify the restore, then call `AbandonServingCandidate`.

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

## Security model

- Private keys are machine-scoped CNG keys and never persisted as files; the
  module never handles private-key bytes.
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
Windows, the elevated lifecycle test `TestCleanupLifecycleElevated` skips when
not running as Administrator, but the trust-store tests
`TestTrustStoreInstallAndVerify`, `TestTrustStoreConflictingCert` and
`TestRemoveNonExistent` use `LocalMachine\Root` directly and are not
elevation-gated. On a machine whose trust store must not be touched, skip them:

```text
go test ./... -skip '^(TestTrustStoreInstallAndVerify|TestTrustStoreConflictingCert|TestRemoveNonExistent|TestCleanupLifecycleElevated)$'
```

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
- The module does not provide a generic TLS/PKI or trust-store framework.

## Troubleshooting

1. **Platform** — is this Windows? On non-Windows the machine functions return
   explicit unsupported-platform errors.
2. **Provisioning** — was `ProvisionMachine()` already run (elevated)? Serving
   startup requires previously persisted machine material.
3. **Elevation** — provisioning and cleanup require Administrator; serving
   startup and read-only verification do not, but the process must be able to
   open the persisted server key.
4. **Trust** — `TrustAbsent` / `TrustConflict` fails closed with
   `ErrTrustNotHealthy`; re-running `ProvisionMachine` does not repair it. See
   [Trust states and recovery](#trust-states-and-recovery). Do not weaken trust
   checks and do not auto-remove a conflicting anchor.
5. **Inconsistent state** — `ErrInconsistentMachineState` is never resolved
   automatically; inspect the state directory and keys before any cleanup.
6. **Renewal** — `ErrRenewalDue` means "run the staged renewal flow". A
   successful `ProvisionMachine` does not mean the certificate was renewed. An
   expired certificate fails closed in `LoadServingMaterial` until a candidate is
   staged, activated, attested and confirmed.
7. **Sentinels** — match with `errors.Is`, never on message text.

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
