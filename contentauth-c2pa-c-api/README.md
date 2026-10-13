# contentauth-c2pa-c-api

A callback-free C ABI for C2PA manifest reading and building, implemented
with [`cimpl`](https://github.com/contentauth/cimpl) for tracked handles,
pointer validation, error conversion, and allocation ownership. Its header
is generated from the Rust API by cbindgen.

## Features

The default build enables both `read` and `build`. Downstream Cargo users
can set `default-features = false` and enable only the API they need:

| Feature | Exported API | Optional subordinate crates |
|---|---|---|
| `read` | `c2pa_sm_read_*`, read requests and session handle | `contentauth-c2pa-file-reader`, `contentauth-c2pa-js-compat` (settings and report JSON) |
| `build` | `c2pa_sm_build_*`, build requests, manifest buffers and exclusion handles | `contentauth-c2pa-file-builder`, `contentauth-c2pa-sign-baseline` (manifest definitions) |

Both use the format registry, primitives, and state-machine engine. A
read-only build does not include the builder or baseline definition parser;
a build-only build does not include the reader or JS compatibility layer.
These features select cohesive workflows, not independently usable parser
or reporting APIs. With neither feature enabled, only the shared step
constants, error vocabulary, and string-allocation cleanup remain.
Test fixtures may pull additional crates into test builds.

```sh
cargo build -p contentauth-c2pa-c-api --no-default-features --features read
cargo build -p contentauth-c2pa-c-api --no-default-features --features build
```

## Architecture

`src/ffi/mod.rs` owns shared error/panic handling and string cleanup.
Its `read` and `build` modules are gated at the module boundary, while
their exports remain available at the crate root. Integration tests are
split the same way: read-only, build-only, shared cleanup, and a round trip
requiring both features. The build and round-trip tests reuse one host
driver from `tests/common`.
Drivers check host-protocol calls and copy returned allocations into owned
results before freeing them. Build-result and read-back assertions live in
the corresponding test files rather than inside the drivers.

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
`build.rs` regenerates it from the exported Rust API. The committed header
declares both APIs unconditionally, so its
contents do not depend on the features used to generate it.

Unused declarations emit no code and require no linked symbol. Cargo
features still control which functions the Rust library exports: calling
an API disabled in that library fails at link time. No C feature macros
are needed. The header retains its include guard and C++ linkage guards.
