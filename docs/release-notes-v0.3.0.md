# Local-TLS v0.3.0

Local-TLS v0.3.0 is a **breaking** release. It separates the CA key from the
server key with per-role CNG key access policies, makes CA-key operations
privileged, adds an explicit migration for existing installations, and moves to
`github.com/keppin-oss/cng` v0.2.1.

Under SemVer pre-1.0 (`0.y.z`) a breaking change is carried by a minor version:
the module path (`github.com/keppin-oss/local-tls`) and the major version are
unchanged. Code that compiled against v0.2.x still compiles, but compiling is
not evidence of operational compatibility. Read
[Upgrading from v0.2.x to v0.3.0](https://github.com/keppin-oss/local-tls/blob/v0.3.0/docs/README.md#upgrading-from-v02x-to-v030)
before upgrading. There is no legacy mode and no compatibility switch.

```
go get github.com/keppin-oss/local-tls@v0.3.0
```

## Breaking changes

- **Per-role key access policies.** New installations create the CA key as
  *privileged-only* (SYSTEM and Administrators) and the server key as
  *service-signer* (SYSTEM, Administrators, LOCAL SERVICE read/execute). The
  CA key is no longer readable by LOCAL SERVICE once it has been created by
  v0.3.0 or migrated.
- **`ReloadMachine` and `StageServerRenewal` are privileged.** Both open the CA
  key and now require LocalSystem or an elevated Administrators member. A
  non-privileged caller gets `ErrPrivilegeRequired`, which is not guaranteed to
  be the first error: some certificate reads and validations run before the CA
  key is opened. Serving must not be elevated for compatibility.
- **Non-privileged serving path.** A non-elevated runtime must use
  `LoadServingMaterial` and `LoadServingCandidate`, which open only the server
  key, and must implement its own renewal-due decision instead of calling
  `ReloadMachine`. `ReloadMachine` and `LoadServingMaterial` are not
  equivalent.
- **Existing state is checked against the policies.** `ProvisionMachine` and
  the CA-key operations fail with `ErrKeyPolicyMismatch` on a CA key that
  still has the pre-v0.3.0 DACL, until it is migrated.

## New API

- `MigrateMachineKeyPolicies()`: explicit, privileged, tighten-only and
  idempotent migration of a pre-v0.3.0 CA key DACL to privileged-only. It
  never creates, regenerates, rotates or deletes keys, never writes
  certificates and never touches `LocalMachine\Root`. It is Windows-only; it
  returns an error on other platforms.
- `ErrPrivilegeRequired`: the operation requires a privileged caller.
- `ErrKeyPolicyMismatch`: a persisted key exists but its DACL does not match its
  role's policy; the key was not modified.

No exported API was removed and no signatures changed.

## Dependency: `github.com/keppin-oss/cng` v0.2.1

- The CNG signer now synchronizes `Sign` and `Close`.
- `Material.Close()` may return an error on its **first** call if a native
  handle cannot be released. The release is not retried; repeated calls are
  harmless and return `nil`.
- `Close()` does not drain callers: close a `Material` only when no TLS
  handshake can use it any longer.

## Upgrading existing installations

Installing the v0.3.0 library alone does **not** remove the exposure of a CA
key created by an earlier release: until the migration succeeds, any LOCAL
SERVICE process can still open it. The privileged installer/updater owns the
cutover, as one serialized administrative step:

1. Stop every process that uses Local-TLS (including older binaries that may
   hold a CA key handle) and make sure no provisioning, renewal or cleanup is
   running.
2. Deploy the v0.3.0 binaries.
3. As LocalSystem or an elevated Administrator, call
   `MigrateMachineKeyPolicies()` once; fail closed on error.
4. Optionally confirm with a privileged `ReloadMachine()`.
5. Restart the services and resume the normal lifecycle.

See
[Migrating key access policies](https://github.com/keppin-oss/local-tls/blob/v0.3.0/docs/README.md#migrating-key-access-policies)
for failure handling, partial state and downgrade notes. There is no
automatic rollback.

## Consumer responsibilities

Local-TLS documents these obligations; it does not implement them.

The privileged installer/updater must:

- run the cutover and the migration described above;
- apply the filesystem ACLs of the state directory: Local-TLS does not set
  Windows ACLs, and write access to the `tls` directory allows tampering,
  denial of service and replay even though it does not grant issuing
  authority.

The runtime that serves TLS (for example the Keppin Agent) must:

- stay non-privileged and use the serving entry points;
- own and serialize the server-certificate renewal (stage, load, activate,
  real handshake, confirm or abandon), excluding concurrent migration,
  provisioning and cleanup; staging a renewal is a privileged operation;
- handle `ErrPrivilegeRequired`, `ErrKeyPolicyMismatch` and the error of
  `Material.Close()`.

Local-TLS does not isolate one LOCAL SERVICE process from another: the server
key is readable by any LOCAL SERVICE process.

## Validation and known limitations

- The offline test suite runs without privileges. On Windows the full
  `go test ./...` is **not** a safe, all-green suite; the documented safe
  suite excludes six machine/trust-store tests (see
  [Validation](https://github.com/keppin-oss/local-tls/blob/v0.3.0/docs/README.md#validation)).
- `TestCleanupLifecycleElevated` is a **known FAIL** under a UAC-filtered
  Administrator token. It is reported as a failure, not masked as a skip.
- The key policies were validated on a disposable Windows machine with the
  limits described in
  [Windows validation of the key policies](https://github.com/keppin-oss/local-tls/blob/v0.3.0/docs/README.md#windows-validation-of-the-key-policies).
  Among them: the exported wrappers were not called with production names and
  paths, the legacy state was reproduced with the legacy CNG API rather than a
  real v0.2.x installation, and no real upgrade or downgrade was run.
- The move to `github.com/keppin-oss/cng` v0.2.1 is covered by build, vet
  and the offline safe suite; the Local-TLS integration with v0.2.1 has not
  been exercised on real machine keys.
- The exported test and smoke helpers still create keys with the legacy
  service-signer DACL and do not follow the production key policies.

Full documentation:
[docs/README.md](https://github.com/keppin-oss/local-tls/blob/v0.3.0/docs/README.md).
