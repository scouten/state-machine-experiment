# contentauth-c2pa-c-api

The canonical callback-free C ABI for synchronous, sans-I/O C2PA reading and
signing. This replaces the experimental `c2pa_sm_read_*` API outright: there
is no legacy shim. It carries the proven C++ binding's `c2pa_sm_session_*`
reader and `c2pa_sm_build_session_*` signing vocabulary, including independent
read and immutable write leases, over `contentauth-c2pa-session-bridge`.
The C++ crate still owns its implementation until the next consolidation phase.

The host owns files, the event loop, HTTP and signing keys. The library never
performs host I/O, spawns a thread or calls a callback. Advance performs bounded
synchronous work. cimpl's handle bookkeeping briefly locks; this is not a
lock-free API.

## Features and implementation

Both `read` and `build` are enabled by default and independently select exports.

| Feature | Exports | Implementation |
|---|---|---|
| `read` | `c2pa_sm_session_*`, `c2pa_sm_reader_*`, read request/reply types | `src/reading/` |
| `build` | `c2pa_sm_build_session_*`, lease operations and sign reports | `src/signing/` |
| neither | version, owned errors and string cleanup | `src/lib.rs` |

Either workflow enables the optional shared bridge dependency. The bridge
currently brings both backends, even when only one C workflow is exported;
these feature flags select the C ABI, not every transitive parser dependency.
With neither feature, the bridge is absent from normal dependencies.
Tests additionally use the shared baseline signing fixtures.
There is no dependency, including a test dependency, on the C++ crate.

```sh
cargo test -p contentauth-c2pa-c-api --all-features
cargo test -p contentauth-c2pa-c-api --no-default-features --features read
cargo test -p contentauth-c2pa-c-api --no-default-features --features build
cargo test -p contentauth-c2pa-c-api --no-default-features
sh contentauth-c2pa-c-api/tests/check-features.sh
```

`build.rs` and `cbindgen.toml` generate
[`include/contentauth_c2pa_c_api.h`](include/contentauth_c2pa_c_api.h).
The header **always declares both workflows**, independent of build features.
Calling a disabled workflow fails at link time. Its enums and structures match
the new ABI; request/reply `kind` and stream fields remain plain integers, so
unknown enum values are rejected rather than crossing Rust as invalid enums.
`tests/header_smoke.c` checks declarations and structure layout as C11 and C++17.

## Interaction and ownership

1. Construct a reader or signing session. Inputs are copied. Read settings may
   be null, empty or whitespace-only to select backend defaults. Formats are
   resolved through the shared registry: JPEG (`image/jpeg`, `image/jpg`,
   `jpeg`, `jpg`) and TIFF/DNG MIME types/extensions, case-insensitively.
   Signing requires a nonempty certificate chain and nonempty entries;
   unlike the experimental C++ constructor, empty chains are rejected up front.
   This is structural validation, not a claim that arbitrary DER is trusted.
2. Advance. `done != 0` means ready to finish. Otherwise, enumerate the **new**
   requests once and copy descriptors and nested payloads before mutating the
   session. An empty new batch while not done means waiting for prior requests,
   not completion.
3. Service any subset of outstanding requests, in any order. Copied replies can
   be released immediately after fulfill. Invalid IDs/kinds leave the original
   request outstanding. Nonempty null or overflowing payloads are rejected.
   Read-side failure text is length-delimited and decoded lossily; signing-side
   failure text must be UTF-8.
4. Finish **consumes a valid session on every outcome**, including an early
   finish, an engine failure, or a null result output. Discard the consumed
   handle. Invalid or busy handles are rejected without consumption. An unsigned
   read succeeds with a null reader. A signed asset yields an immutable reader;
   a build yields an immutable sign report, not a second copy of the output asset.

All opaque handles, errors and returned strings use cimpl tracking. Null,
stale and wrong-type handles are rejected without dereferencing arbitrary
caller memory. Common/reader void frees ignore invalid or busy handles; signing
frees report errors. Fallible operations return an integer status and optionally
an independently owned error. Free errors with `c2pa_sm_error_free`; error
message/name pointers borrow the error. Reader JSON and label strings are
independent allocations freed with `c2pa_sm_string_free`, and outlive the reader.
String cleanup rejects non-string handles without destroying their owners.

**Diagnosable failures:** `c2pa_sm_session_phase` and
`c2pa_sm_build_session_phase` return an owned string describing the session's
current phase, or the phase where it failed, freed with `c2pa_sm_string_free`.
Errors reported after failure retain the original phase and cause. The wording
is intended for logs and is not a stable interface.

Sessions may move between threads, but a host must serialize operations on
each session and all use of borrowed request views. Request borrows end at the
next advance, fulfill, finish or free; read/write lease acquisition preserves
these views. Immutable readers/reports support shared
access, but their storage must not be freed while borrowed views are in use.
Panics in fallible boundary operations become owned panic errors.

## Signing I/O leases

Ordinary byte replies copy. For an outstanding read, `c2pa_sm_build_read_acquire`
returns initialized exact-size writable storage owned independently of the
session. A request can acquire only one lease, even if abandoned. After **all**
I/O and writable access stops, `c2pa_sm_read_seal` consumes/nulls the lease and
returns a completed read. `c2pa_sm_build_fulfill_read` moves that allocation into
its original session/request without copying. Rejected counts, IDs, wrong
sessions or busy handles preserve ownership; successful transitions null the
input handle. Fulfillment rejected after session failure also preserves the
completed handle and its payload. Abandoned and completed storage can be freed
after cancellation.

`c2pa_sm_build_write_acquire` retains an outstanding write's **immutable** bytes.
Multiple leases share the same storage. They survive write acknowledgment,
advance, failure, finish and cancellation. The host must stop its I/O before
freeing each lease; it must never mutate the returned bytes. Acquiring a lease
does not acknowledge the write: fulfill `WRITTEN` only after the entire payload
is visible to subsequent reads.

Signing requests contain the full COSE Sig_structure, not a digest. Return
fixed-width `r || s` for ES256, not DER. Timestamp requests contain an encoded
RFC 3161 TimeStampReq; return the complete DER TimeStampResp.

## Validation and tests

The shared backend's online OCSP default is **off**; set
`{"verify":{"ocsp_fetch":true}}` to request it explicitly. The host answers
the OCSP URL/body just like any other request. Tests exercise authenticated
good/revoked responses, malformed bodies and an unreachable responder without
network access, and distinguish their exact validation statuses.

Tests that need the crate's internals sit beside the code they test:
`src/tests.rs` (common tracked ownership and panic behavior),
`src/reading/tests.rs`, and `src/signing/tests.rs` with topic files under
`src/signing/tests/` (`constructor`, `replies`, `report`, `handles`). They cover
the proven ABI scenarios, its explicit canonical constructor differences,
busy/stale/wrong-type handles, rejected-operation ownership, cross-thread
movement and allocation reuse. `src/roundtrip/` signs and reads back using only
exported functions and types, as a C host would, and checks timestamps, exact
baseline manifest fields, OCSP outcomes and JPEG/TIFF/DNG round trips. It lives
in the crate rather than `tests/` because an integration-test binary links a
second instrumented copy of the `#[no_mangle]` exports, which makes
`cargo llvm-cov` misreport them as uncovered.
The local public OCSP fixtures in `tests/fixtures` use a test key protecting
nothing; regenerate with
`sh contentauth-c2pa-c-api/tests/fixtures/generate-ocsp-chain.sh`.
