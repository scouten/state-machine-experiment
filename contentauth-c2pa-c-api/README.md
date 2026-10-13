# contentauth-c2pa-c-api

A callback-free C ABI for C2PA manifest reading and building, implemented
with [`cimpl`](https://github.com/contentauth/cimpl) for tracked handles,
pointer validation, error conversion, and allocation ownership. Its header
is generated from the Rust API by cbindgen.

## Architecture

This crate exposes the synchronous sans-I/O state machines
(`FileReadSession` and `FileBuilderSession`) over an FFI boundary using
opaque pointers, non-owning request arrays, and plain integer request IDs.

Key characteristics:
- **Zero threads created**: Contains no thread-spawning calls, no async
  runtimes (tokio, rayon), and no background worker pools. All CPU-bound
  parsing and cryptographic hashing happen synchronously on the caller's
  thread.
- **Zero callbacks**: Instead of passing C function pointers across FFI,
  the API uses step-by-step state machine transitions (`c2pa_sm_*_advance`,
  `c2pa_sm_*_fulfill_*`, `c2pa_sm_*_finish`).
- **Caller-owned I/O**: The host fulfills I/O requests (`read`, `write`,
  `get_length`), network requests (`ocsp`, `timestamp`), and cryptographic
  signing requests (`sign`) using its own native async mechanisms (e.g.
  Swift `async/await`, `URLSession`, Apple `CryptoKit`).
- **Tracked ownership**: Session handles and returned strings and byte
  buffers use cimpl's allocation registry. Request data pointers borrow the
  session's internal buffers for the current turn; the exclusion array is
  borrowed from a tracked exclusion-list handle.
- **Panic safety**: All `extern "C"` functions catch panics at the boundary
  and translate them into integer return codes and error messages.
- **Concurrent access**: cimpl serializes handle borrows. A host should not
  use one session concurrently, and must not retain request pointers beyond
  their documented lifetime.

The generated C header is located in
[`include/contentauth_c2pa_c_api.h`](include/contentauth_c2pa_c_api.h);
`build.rs` regenerates it from the exported Rust API. The Swift package
contains a copy of this generated header for Swift Package Manager.
