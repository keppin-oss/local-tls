# Local-TLS v0.5.0

Local-TLS v0.5.0 moves to `github.com/keppin-oss/cng` v0.5.1 and separates
opening, creating and deleting the CA and server keys. A key is never created
as a side effect of an open, never adopted by a create, and never deleted
without verifying its public key against a recorded identity. This is a
**breaking** release with no compatibility layer: the key-store interfaces
change, `MigrateMachineKeyPolicies` is removed, and cleanup behaves differently
(below).

```
go get github.com/keppin-oss/local-tls@v0.5.0
```

## Key store: open, create and delete are separate

- `MachineKeyStore` now has `OpenCAKey` and `OpenServerKey`, which never create
  a key, and `CreateCAKey` and `CreateServerKey`, which never open or adopt an
  existing key: a key already persisted under the name returns the new sentinel
  `ErrKeyExists` and is left untouched. `MachineKeyStore` embeds
  `MachineKeyDeleter`.
- `MachineKeyDeleter` is now `DeleteCAKey(expectedSPKI []byte)` and
  `DeleteServerKey(expectedSPKI []byte)`. cng verifies the role policy and that
  the key's public key is `expectedSPKI` on the handle it deletes. A check that
  does not pass, or cannot be completed, returns the new sentinel
  `ErrDeleteVerificationFailed` and deletes nothing.
- The identity of a created key is the DER SubjectPublicKeyInfo of its signer,
  `x509.MarshalPKIXPublicKey(signer.Public())`. A caller records it before using
  the key and never derives it by reopening the key name.
- Removed: `LoadOrCreateCAKey`, `LoadOrCreateServerKey` and
  `MigrateMachineKeyPolicies` (with its non-Windows stub).

## First install

`ProvisionMachine` creates both keys and records each key's public key right
after its create. A key already persisted under a Local-TLS name fails the
install with `ErrKeyExists`; it is never certified.

A first install that fails before both certificate DERs are persisted is rolled
back: it releases its key handles, removes the DERs it wrote and deletes only
the keys it created, each through its recorded public key. For example, when the
server key already exists, only the new CA key is deleted.

- When the rollback cannot complete, the error also matches the new sentinel
  `ErrRollbackIncomplete`. It keeps the primary cause and names each key left
  behind by its role and, when it could be encoded, the SHA-256 of its public
  key.
- A key handle whose release fails is reported as the new sentinel
  `ErrKeyReleaseUnconfirmed`, with its role, and is not closed again.
- After both DERs are persisted nothing is rolled back. A failure to install the
  trust anchor, or a CA handle whose release is not confirmed (the trust anchor
  is then not installed), leaves the keys and DERs for `CleanupMachine`.

Existing-state provisioning opens the keys only.

## Cleanup: verified deletes

`CleanupMachine` and `CleanupMachineBySHA256` read both certificate DERs before
changing anything, and delete each key through the public key of its
certificate.

- **Behavior change:** a key whose certificate DER is missing, unreadable or
  does not parse is no longer deleted. Its deletion is reported as the new
  sentinel `ErrKeyDeletionNotCompletable`, and the other key is still
  processed.
- The fingerprint passed to `CleanupMachineBySHA256` identifies the trust
  anchor, never a key. A CA DER on disk whose fingerprint is not that one does
  not identify the CA key.
- **Behavior change:** the state directory is now kept unless the trust anchor
  removal **and** both key deletions are confirmed. Earlier releases removed it
  even when the trust anchor removal had failed.
- A cleanup repeated after a complete one finds no DER and deletes nothing
  (`ErrKeyDeletionNotCompletable`).

The smoke helpers follow the same rules.

## Errors

- Every mapped CNG error keeps the cng sentinel and the native
  `*windowscng.NCryptError` in its chain. In particular, an `ErrKeyNotFound`
  error now also matches `windowscng.ErrKeyNotFound`.
- New sentinels: `ErrKeyExists`, `ErrDeleteVerificationFailed`,
  `ErrKeyDeletionNotCompletable`, `ErrRollbackIncomplete`,
  `ErrKeyReleaseUnconfirmed`.
- Inherited from cng v0.5: the policy check is exact. A key with extra access
  entries, an unprotected DACL or access masks outside the policy no longer
  opens (`ErrKeyPolicyMismatch`). A CA key that still carries the service-signer
  DACL of a release before v0.3.0 can no longer be tightened in place; it fails
  with `ErrKeyPolicyMismatch`, is refused by the verified delete, and needs an
  administrative recovery.

## Dependency: `github.com/keppin-oss/cng` v0.5.1

Open, create, delete and apply are four primitives that take the policy as a
parameter. `Create` never overwrites, and `Delete` requires the expected public
key. Public-key export is done once per open or create, and native reads are
bounded (signature, public key, security descriptor).

## Test helpers and `cmd/verify`

- `TestCreateKey`, `TestOpenKey` and `TestDeleteKey` use an explicit
  service-signer policy. `TestDeleteKey` now takes the expected public key, and
  `TestKeySPKI` returns it.
- `cmd/verify -create` prints the new key's public key as `SPKI=<base64>`.
  `-delete` requires exactly one of `-spki <base64>` or `-spki-file <path>`, and
  exits 2 without one.

## Continuous integration

A GitHub Actions workflow builds, vets (amd64 and 386) and tests the module on
Windows, and checks formatting, builds, vets and tests it on Linux. The Windows
runner's token is elevated, and `KEPPIN_TRUST_ELEVATED_REQUIRED=1` makes the
`LocalMachine\Root` tests fail instead of skipping without privileges. The
tests with real machine CNG keys do not run in CI.

## Validation and known limitations

- Offline: the suite passes without privileges and, with an elevated token, with
  the trust-store tests included.
- Live, with the Microsoft Software Key Storage Provider, on Windows 11 Pro 25H2
  (build 26200) and Windows Server 2025 Standard 24H2 (build 26100):
  - the full suite elevated, with the smoke lifecycle and the serving-close test
    using real machine keys, and no test skipped;
  - `cmd/verify` with an elevated token, a non-elevated token and LOCAL SERVICE.
    Every case behaved as expected: create, create on an existing name, open,
    sign, delete with a wrong public key, delete with the recorded one.
  - On Windows Server 2025 the non-elevated runs used a restricted token
    (`runas /trustlevel`) at high integrity, not a UAC-filtered token.
- The live runs validated the same production logic before the public
  module-path rewrite. The serving-close test and its environment variable and
  key prefix ran under internal names that differ from the published ones.
- Not validated: other Windows builds or editions, other key storage providers,
  impersonation, LOCAL SERVICE as a real service (it ran from a scheduled task),
  and Schannel, CryptoAPI, .NET or browsers.
- A key create does not reserve the name: two overlapping creators can both
  succeed. The single-writer contract of `ProvisionMachine` and cleanup still
  applies.
- If the process stops between a key create and the DER writes, a key is left
  without any persisted record, and Local-TLS cannot delete it.

See
[Upgrading from v0.4.x to v0.5.0](https://github.com/keppin-oss/local-tls/blob/v0.5.0/docs/README.md#upgrading-from-v04x-to-v050).

Full documentation:
[docs/README.md](https://github.com/keppin-oss/local-tls/blob/v0.5.0/docs/README.md).
