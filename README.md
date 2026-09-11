# Local TLS

Machine-scoped TLS material lifecycle for localhost HTTPS on Windows.

`local-tls` owns the creation, persistence, verification, renewal, and exact
cleanup of the TLS material used to serve localhost HTTPS on Windows. Its
centerpiece is a self-signed local CA certificate and a CA-signed `localhost`
server certificate, backed by machine-scoped CNG/KSP signing keys whose private
material never leaves Windows CNG.

## Scope

- A Local TLS-owned **self-signed CA certificate** and a CA-signed
  **`localhost` server certificate** (ECDSA P-256).
- Machine-scoped persisted **CA and server signing keys** via Windows CNG/KSP
  (Microsoft Software Key Storage Provider); private keys are non-exportable.
- Persistence of **public certificate DER only** on the production machine (CNG)
  path — private keys stay in CNG.
- Installation, verification, and **exact** removal of the local CA trust anchor
  in `LocalMachine\Root`.
- Fail-closed provisioning, serving-startup, reload/renewal, and cleanup flows.

## Non-goals

`local-tls` is **not** a general-purpose TLS/PKI framework, a certificate
manager, or a trust-store framework. It does not own enterprise CA enrollment,
enterprise-vs-local selection policy, low-level reusable CNG/KSP key custody, the
long-lived HTTPS listener runtime, or unrelated application state.

## Quick start

```go
import "github.com/keppin-oss/local-tls"
```

The package is named `localtls`. Machine provisioning is performed once
(elevated); ordinary HTTPS serving startup uses `LoadServingMaterial`. Complete
compile-safe examples live under [`examples/`](examples/):

- [`examples/serving`](examples/serving/main.go) — normal HTTPS serving startup.
- [`examples/provision`](examples/provision/main.go) — elevated provisioning/repair.
- [`examples/fingerprint`](examples/fingerprint/main.go) — fingerprint utilities and cleanup handoff.

## Resources

- **Technical documentation:** [`docs/README.md`](docs/README.md)
- **Examples:** [`examples/`](examples/)
- **Module:** `github.com/keppin-oss/local-tls`
- **License:** [Apache License 2.0](LICENSE)
