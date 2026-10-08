# contentauth-c2pa-ephemeral-cert

A throwaway Ed25519 CA and end-entity certificate chain for local C2PA
signing, adapted from Gavin Peacock's `c2pa-core` sample
(`c2pa-sign-sample/src/ephemeral_cert.rs`). **Anchored to nothing** — a
verifier must be told to trust `ca_pem`.

The one change in kind: entropy and the clock are *parameters* (a `fill`
closure and `Params::now_unix`) rather than `getrandom` and
`OffsetDateTime::now_utc()`, so the crate is sans-I/O like the rest of the
workspace and, given the same inputs, deterministic. Built on `rcgen` for
DER only (no `ring`, no OpenSSL), so it also builds for Wasm.
