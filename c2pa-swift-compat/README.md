# c2pa-swift-compat

An experimental Swift package implementing an alternative foundation for
`c2pa-swift`, built on `contentauth-c2pa-c-api` and the sans-I/O state
machine architecture.

## The Problem in Existing c2pa-swift / c2pa-rs

In the existing `c2pa-swift` SDK (backed by `c2pa-rs` through UniFFI):
1. **Thread creation policy violations** (`c2pa-swift#30`, `c2pa-rs#1660`):
   Rust spawns its own POSIX threads (tokio worker pool, rayon, or background
   threads) without Darwin Mach QoS tags, triggering priority inversions and
   crashing or hanging under strict iOS/macOS energy and scheduling policies.
2. **Cooperative thread pool starvation**: `C2PAContext` and `WebServiceSigner`
   bridge asynchronous Swift calls to synchronous Rust callbacks using
   `DispatchSemaphore.wait()`. In Swift Concurrency, blocking a cooperative
   pool thread with a semaphore violates Apple's forward-progress guarantee
   and causes process deadlocks.

## The Sans-I/O State Machine Solution

`c2pa-swift-compat` solves both issues fundamentally:
- **Zero Rust threads**: The underlying Rust library (`contentauth-c2pa-c-api`)
  never spawns threads. All state transitions, JUMBF decoding, CBOR validation,
  and hard-binding verification execute on whatever Swift thread or `Task`
  invoked them, naturally preserving the caller's Quality of Service (QoS).
- **Swift owns all I/O and Concurrency**: Swift drives the state machine in a
  standard `while` loop with native `await` calls:
  - Asset I/O is serviced asynchronously via `AsyncByteSource` and `AsyncByteSink`.
  - OCSP revocation checks and RFC 3161 timestamping are performed via `URLSession`.
  - Cryptographic signatures are produced via `AsyncSigner` (e.g. `CryptoKitP256Signer`
    or Secure Enclave `SecureEnclaveSigner`).
- **Full Cancellation Support**: When a Swift `Task` is cancelled, the loop
  exits immediately and frees the Rust session without hanging or leaking.
- **Cooperative Concurrency**: Multiple `Reader` or `Builder` tasks can
  interleave at their native async I/O boundaries without semaphore waits
  or blocking I/O. cimpl's handle registry serializes concurrent borrows;
  each session is driven by one task at a time.

The SwiftPM C header is copied from the cbindgen-generated header in
`contentauth-c2pa-c-api/include/contentauth_c2pa_c_api.h`.

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                   c2pa-swift-compat                    │
│  Reader / Builder / Stream / Signer / C2PAContext     │
│  (Swift 6 Strict Concurrency, Swift Testing)           │
└───────────────────────────┬────────────────────────────┘
                            │ Swift C Bridge
┌───────────────────────────▼────────────────────────────┐
│               contentauth-c2pa-c-api                   │
│   c2pa_sm_read_* / c2pa_sm_build_* (C ABI, staticlib)  │
└───────────────────────────┬────────────────────────────┘
                            │ Rust
┌───────────────────────────▼────────────────────────────┐
│      FileReadSession / FileBuilderSession (Sans-I/O)   │
│             contentauth-state-machine                  │
└────────────────────────────────────────────────────────┘
```
