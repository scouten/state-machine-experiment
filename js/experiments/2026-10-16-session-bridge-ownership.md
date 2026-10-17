# Neutral session bridge: naming and ownership

Migrated from the combined findings dated 2026-10-16. Measurements and test
counts below describe the original run, not a new execution.

## Naming and ownership finding

`NodeSession` was named after its first consumer, not a Node dependency. Its
request-handle and plain-data contract is now owned by `ReadSessionBridge` in
`contentauth-c2pa-session-bridge`; `BuildSessionBridge` owns the signing
vocabulary and report. Shared compatibility context, manifest-store and error
types live beside both bridges. Neon and Wasm are consumers, not owners. See
[current bridge ownership](../README.md#neutral-session-bridge).

The protocol could also serve non-JavaScript hosts, with language-specific
adapters for ABI conversion and ownership. At the time of the original proof, that portability was an architectural
possibility rather than a tested non-JavaScript binding: current Rust types are not a universal ABI,
and c2pa-js compatibility conventions should not be required by other hosts.
See [reuse beyond JavaScript](../README.md#reuse-beyond-javascript).

## Subsequent evidence

The merged [C++ reader binding](../../contentauth-c2pa-cpp/README.md) now
consumes the read bridge through a C ABI with blocking, threaded and coroutine
hosts. Python remains prospective. C++ signing is not implemented.
This is an architectural finding, not a performance benchmark; the
[read](2026-10-16-shared-host-read.md) and
[signing](2026-10-16-shared-host-signing.md) proofs provide the original JS evidence.

[All experiment reports](README.md)
