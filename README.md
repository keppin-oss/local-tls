# Local TLS

Machine-scoped TLS material lifecycle for localhost HTTPS on Windows.

## Scope

- A self-signed local CA and a CA-signed `localhost` server certificate
  (ECDSA P-256).
- Machine-scoped, non-exportable CA and server keys in Windows CNG/KSP; only
  public certificate DER is persisted on disk.
- Exact install, verification and removal of the CA in `LocalMachine\Root`.
- Fail-closed provisioning, serving startup, reload, cleanup, and staged
  server-certificate renewal confirmed by the consumer.

## Non-goals

Not a general-purpose TLS/PKI framework, certificate manager or trust-store
framework. It does not own enterprise CA enrollment, the HTTPS listener runtime
or unrelated application state.

## Quick start

```go
import "github.com/keppin-oss/local-tls"
```

Package `localtls`. Provision once (elevated), then serve with
`LoadServingMaterial`. See [`examples/`](examples/):

- [`serving`](examples/serving/main.go) — HTTPS serving startup.
- [`provision`](examples/provision/main.go) — elevated first install / verification.
- [`fingerprint`](examples/fingerprint/main.go) — fingerprints and cleanup handoff.

## Upgrading from v0.1.x

v0.2.0 has breaking behavior changes; see
[Upgrading from v0.1.x](docs/README.md#upgrading-from-v01x).

## Resources

- [Technical documentation](docs/README.md)
- License: [Apache License 2.0](LICENSE)
