// Package identity centralises the product-branding constants used by the
// Local TLS module. These values identify product/runtime state owned by this
// standalone module: persisted CNG key names, certificate subject DNs,
// %ProgramData% paths, and the test/smoke key namespaces.
//
// Several of these constants produce persisted Windows machine state
// (CNG key names, certificate subject DNs, %ProgramData% paths, and
// certificate trust anchors). Changing them after first external release
// would create parallel identities and require explicit migration/cleanup
// behaviour. Every exported value in this file should therefore be treated
// as a compatibility contract.
//
// Smoke/test identities remain explicitly isolated from production
// identities — do not collapse them into one freely-concatenated string.
package identity

// ProductName is the display / product name used in UI, logs and
// user-facing text. It is not used to generate security-sensitive
// persisted identifiers and is safe to change at any time.
const ProductName = "Keppin"

// FileSystemDir is the short directory name used in filesystem paths
// (e.g. %ProgramData%\Keppin\...). It MUST NOT be changed after the first
// external release without an explicit migration procedure.
const FileSystemDir = "Keppin"

// ProdCAKeyName is the full persisted production CNG CA key name.
// This identity is stored in the Microsoft Software KSP and MUST NOT
// change after the first external release without an explicit migration
// procedure.
const ProdCAKeyName = "Keppin.Agent.LocalHTTPS.CA.v1"

// ProdServerKeyName is the full persisted production CNG server key name.
// Same persistence constraints as ProdCAKeyName.
const ProdServerKeyName = "Keppin.Agent.LocalHTTPS.Server.v1"

// TestKeyNamespace is the enforced prefix for ALL test-only CNG keys
// (smoke and non-smoke). The guard in TestCreateKey rejects any key name
// that does not start with this string, isolating test keys from production
// keys by construction. The trailing dot prevents prefix collisions.
const TestKeyNamespace = "Keppin.Test."

// SmokeKeyNamespace is the enforced prefix for smoke-test CNG keys.
// It is a subset of TestKeyNamespace and is additionally validated by the
// smoke provisioning path. The trailing dot prevents prefix collisions.
const SmokeKeyNamespace = "Keppin.Test.Smoke."

// SmokeCAKeyName is the full persisted smoke-test CNG CA key name.
const SmokeCAKeyName = "Keppin.Test.Smoke.LocalHTTPS.CA.v1"

// SmokeServerKeyName is the full persisted smoke-test CNG server key name.
const SmokeServerKeyName = "Keppin.Test.Smoke.LocalHTTPS.Server.v1"

// CertOrganization is the certificate subject Organization value used in
// both the CA and server certificates. It is embedded in persisted X.509
// certificates and in the LocalMachine\Root trust store.
const CertOrganization = "Keppin"

// CACertCommonName is the CA certificate subject Common Name. It is embedded
// in the persisted CA certificate and in the LocalMachine\Root trust store.
const CACertCommonName = "Keppin Local Root CA"

// EnvPrefix is the prefix shared by all Keppin environment variable names.
const EnvPrefix = "KEPPIN"

// TestSignMessage is the message signed during the LocalService ACL
// verification smoke test. It is not a persisted identity.
const TestSignMessage = "Keppin CNG ACL verification"
