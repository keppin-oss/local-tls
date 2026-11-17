# Local-TLS v0.4.0

Local-TLS v0.4.0 constrains the CA it issues. The CA certificate now carries
critical name constraints and a serverAuth-only extended key usage, and the
module rejects, fail-closed, any CA that does not. It also moves to
`github.com/keppin-oss/cng` v0.3.1. There is one new exported identifier,
`ErrCANotConstrained`, and **existing installations need to replace their CA**
(below).

```
go get github.com/keppin-oss/local-tls@v0.4.0
```

## CA name constraints and EKU

A CA issued by v0.4.0 has:

- extended key usage exactly `[serverAuth]`;
- critical name constraints: permitted DNS `localhost`, and permitted IP ranges
  exactly `127.0.0.1/32` and `::1/128`.

The server certificate keeps its fixed identity (`localhost`, `127.0.0.1`,
`::1`), so it satisfies the constraints.

### Behavior change: existing CAs are rejected

A CA issued by v0.3.1 or earlier has neither the constraints nor the EKU. It is
rejected on every path that reaches the common validator: serving, renewal
staging, candidate load and confirm, and provisioning on existing state. The
error is the new sentinel `ErrCANotConstrained`, distinct from
`ErrCertificateNotValidNow` and `ErrTrustNotHealthy`. A time-invalid CA is still
reported as such first. Nothing is regenerated or rewritten.

To upgrade an installation, replace the CA with cleanup and a new provisioning
(the trust anchor and the server certificate are replaced with it). Callers that
switch on the sentinels returned by the load paths should handle the new one.
The provisioning pre-checks only verify the presence and coherence of the
persisted material; the rejection comes afterwards, from the common validator.

### What the constraints do not do

- They do not stop a holder of the CA key from signing. They make verifiers that
  apply the anchor's constraints reject other names.
- The DNS constraint is a subtree, so it also admits names under `localhost`
  (for example `foo.localhost`); the exact SAN check is `validateSAN`.
- The subject DN is not covered by the constraints.
- Go applies them (verified offline). Schannel/CryptoAPI, .NET and browsers were
  not validated and must not be assumed to behave the same.
- There is no defence against a compromised SYSTEM or administrator, who can
  also change the trust store.

Details:
[Certificate & key lifecycle](https://github.com/keppin-oss/local-tls/blob/v0.4.0/docs/README.md#certificate--key-lifecycle).

## Dependency: `github.com/keppin-oss/cng` v0.3.1

- Native failures are typed (`*windowscng.NCryptError`, reachable with
  `errors.As`) and `windowscng.ErrPostWriteVerification` is public. Local-TLS
  still classifies only by the cng sentinels: a bare native error is never
  turned into `ErrKeyNotFound`, and `ErrPostWriteVerification` is passed through
  unchanged.
- A persisted security-descriptor read that reports 0 bytes, and an Export
  Policy read whose reported size is not exactly 4 bytes, fail closed: the key
  is not opened and no signer is returned.
- A non-privileged caller whose key finalization is denied, followed by a delete
  that reports `NTE_BAD_KEYSET`, no longer produces `ErrCleanupFailed`.
- Provisioning and policy changes on the same key must be serialized by the
  caller, also across processes.

How these surface through Local-TLS:
[Lifecycle & ownership of `Material`](https://github.com/keppin-oss/local-tls/blob/v0.4.0/docs/README.md#lifecycle--ownership-of-material).

## Tests

- New offline tests cover the CA template, leaf acceptance and out-of-constraint
  rejection through Go's verifier, EKU misuse, a fail-closed matrix of missing or
  wrong constraints, and rejection on the serving, candidate and renewal-staging
  paths and on provisioning of existing state (a Windows test with fakes).
- New mapper tests cover the typed native errors and
  `ErrPostWriteVerification` of cng v0.3.x.

## Validation and known limitations

- The offline suite runs without privileges; the harness tests also with the
  race detector.
- This release was not run live on Windows: the cng v0.3.x behaviors above and
  the interaction of the constrained CA with the Windows trust store, Schannel,
  .NET and browsers were not validated against a real Key Storage Provider.
- The limits of the v0.3.0 key-policy validation and of the v0.3.1 Windows
  validation still apply.

Full documentation:
[docs/README.md](https://github.com/keppin-oss/local-tls/blob/v0.4.0/docs/README.md).
