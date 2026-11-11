# Local-TLS v0.3.1

Local-TLS v0.3.1 is a patch release. It moves to `github.com/keppin-oss/cng`
v0.2.2, makes the outcome of the manual `cmd/verify -open` check independent of
error text, and hardens the machine tests. There is no API change and no
migration step; library behavior changes only on error paths, through cng
v0.2.2 (below).

```
go get github.com/keppin-oss/local-tls@v0.3.1
```

## Dependency: `github.com/keppin-oss/cng` v0.2.2

- When a key open-or-create call creates a **new** key and then fails to
  verify it or to build its signer, the CNG layer attempts once to delete that
  new key instead of leaving it behind. If that deletion fails, the error also
  matches `windowscng.ErrCleanupFailed`. Existing keys and keys that are only
  opened are never deleted on these paths.
- Public-key export returns an error instead of panicking when the provider
  reports an invalid size or an invalid or truncated blob.
- How these errors surface through Local-TLS, including the one case in which
  `ErrCleanupFailed` is kept as text only, is described in
  [Lifecycle & ownership of `Material`](https://github.com/keppin-oss/local-tls/blob/v0.3.1/docs/README.md#lifecycle--ownership-of-material).

## `cmd/verify -open`

The manual testing CLI now reports one of three outcomes, with exit codes that
are the CLI's own contract:

| Outcome | Exit | Meaning |
|---|---|---|
| `OPENED` | 0 | the open succeeded |
| `NOT_OPENABLE` | 3 | the error matches the `ErrKeyNotFound` sentinel |
| `ERROR` | 1 | any other failure, explicit native denials included |

The classification never parses error text. The Microsoft Software KSP reports
NTE_BAD_KEYSET both for an absent key and for a key the caller may not open, so
`NOT_OPENABLE` alone does not prove denial.

**Exit codes changed meaning.** In v0.3.0 exit 0 meant that the open was
denied, as recognized from the error text, and exit 1 covered everything else, a
successful open included. In v0.3.1 exit 0 means that the open succeeded, exit 3
that the key is absent or not accessible, and exit 1 any other failure. The
`DENIED` output is gone. Scripts that check the exit code or parse the output
must be updated. The old codes are not restored: on the Software KSP the error
text did not distinguish a denied key from an absent one.

## Tests

- `TestCleanupLifecycleElevated` now requires `KEPPIN_SMOKE_DIAG_DIR` (a
  durable diagnostics directory outside the test temporary directory) and is
  otherwise skipped (NOT EXECUTED). After a failed release of the serving signer
  it deletes no key, removes at most the exact CA trust anchor, and records the
  outcome of every artifact.
- New live test `TestServingCloseRaceElevated`: TLS handshakes concurrent with
  `Material.Close` on a real CNG test key and an in-memory CA (no
  `LocalMachine\Root`). It runs a consumer-drain scenario, a deterministic race
  and stress rounds, and deletes its single key only after a confirmed release.
  It runs only with `KEPPIN_SERVING_CLOSE_DIAG_DIR` and a privileged caller.
  Its verifier, scenarios and cleanup decisions are covered offline by
  `TestServingCloseHarness*`.
- The safe suite now excludes seven machine/trust-store tests (see
  [Validation](https://github.com/keppin-oss/local-tls/blob/v0.3.1/docs/README.md#validation)).

## Validation and known limitations

- The offline suite and the new harness tests run without privileges, also
  with the race detector.
- Before publication, binaries built from the pre-publication tree (different
  module path, harness identifiers and log texts; no functional difference)
  were run once on a disposable Windows 11 VM:
  `cmd/verify -open` across principals, `TestCleanupLifecycleElevated` (two
  cycles; and the documented failure under a UAC-filtered token), and
  `TestServingCloseRaceElevated` built with `-race`. Details and limits:
  [Windows validation of v0.3.1](https://github.com/keppin-oss/local-tls/blob/v0.3.1/docs/README.md#windows-validation-of-v031).
- The harness observes Sign/Close overlaps at its own wrapper, not inside the
  native signer; `-race` covers Go state only.
- The cng v0.2.2 rollback and export guard were not triggered on a live KSP.
- The limits of the v0.3.0 key-policy validation still apply.

Full documentation:
[docs/README.md](https://github.com/keppin-oss/local-tls/blob/v0.3.1/docs/README.md).
