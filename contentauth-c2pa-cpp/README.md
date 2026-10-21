# contentauth-c2pa-cpp

An experimental C++ binding for the sans-I/O C2PA reader and builder, written to answer
one question: **can the session model express asynchronous and threaded
behavior that a callback-based C++ API cannot?**

It is **C++** (`include/contentauth/`) over the canonical C ABI of
[`contentauth-c2pa-c-api`](../contentauth-c2pa-c-api/) (its static library and
generated `contentauth_c2pa_c_api.h`), header-only except for signing and the
thread pools (`cpp/src/`, built as `c2pa_sm_cpp`). CMake builds that library
with cargo and links it; this directory's own Rust ABI (`src/`, `Cargo.toml`)
is no longer linked and awaits removal in the final consolidation phase, as are
its hand-written `include/contentauth_c2pa_sm*.h` headers. See the
[consolidation plan](../docs/c-api-consolidation-plan.md).

| Header | Standard | Provides |
|---|---|---|
| `c2pa_sm.hpp` | C++17 | `Session`, `Reader`, the request/reply vocabulary, `Exception`, the blocking driver `read()`, hosts for memory / `std::istream` / files |
| `c2pa_sm_async.hpp` | C++17 | `AsyncHost`, `Reading`, `Mailbox`, `read_parallel`, `read_future`, `PooledHost` |
| `thread_pool.hpp` | C++17 | the `ThreadPool` interface, `make_simple_thread_pool`, and on Apple platforms `make_apple_thread_pool` (GCD) |
| `c2pa_sm_coro.hpp` | C++20 | `Task`, `co_read`, `spawn` |
| `c2pa_sm_sign.hpp` | C++17 | `BuildSession`, blocking memory / stream / POSIX file hosts and signing driver |
| `c2pa_sm_sign_async.hpp` | C++17 | `Building`, `BuildMailbox`, pooled / future / parallel signing |
| `c2pa_sm_sign_coro.hpp` | C++20 | `co_build_and_sign`; link the separate `c2pa_sm_coro` target |

```cpp
#include "contentauth/c2pa_sm.hpp"

c2pa::sm::FileHost host("photo.jpg");
auto reader = c2pa::sm::read(c2pa::sm::Session("image/jpeg"), host);
if (reader) std::cout << reader->json();   // nullopt: no Content Credentials
```

C++ drivers support reading and signing; the signing ABI and C++ APIs are
described in [Signing contract](#signing-contract). Build with `./build.sh`, or
build and run all C++ tests with `./test.sh`. Both scripts forward extra
arguments to CMake's configure step, e.g. `./test.sh -DCMAKE_BUILD_TYPE=Release`
(needs cargo, CMake ≥ 3.16, OpenSSL Crypto development headers and a C++20
compiler for the tests and coroutine pieces; non-coroutine APIs and the compiled
core retain their C++17 baseline). Tests need GoogleTest as described below.
To build the library and examples without GoogleTest, use
`./build.sh -DBUILD_TESTING=OFF`.

### Signing example

On POSIX, `examples/sign.cpp` builds as `c2pa_sm_sign`. It uses only public
library headers and supplies an OpenSSL-backed ES256 callback in the host:

```sh
./build/c2pa_sm_sign input.jpg output.jpg definition.json certificate.der key.pem
```

The definition includes the required instance ID, label, generator and
assertions. The certificate is DER and the key is an unencrypted ES256 PEM;
encrypted keys are rejected without prompting. The output is published
atomically, then read back with the supplied certificate explicitly trusted,
and its validation JSON is printed. The example exits zero only when the
read-back validation state is `Trusted`; any other state reports a verification
error and exits 2. It checks the typed `Reader::validation_state()` accessor,
not the JSON's indentation or text. Verification happens after publication, so a failed check
does not remove the output. This demonstrates caller-selected trust,
not independent proof that a supplied certificate is trustworthy. An optional
last argument supplies Unix seconds for reproducible validation; otherwise the
host uses the system clock. No HTTP transport is supplied, so a definition
requesting a timestamp fails closed rather than omitting it.

CTest runs the example with the baseline fixtures and a fixed validation time,
requiring `validation_state: Trusted`. A mismatched P-256 key test requires an
`Invalid` report, a verification-error diagnostic and exit 2; its temporary key
and output are removed afterward. The usage-error test also checks a nonzero
exit. `./test.sh` and CI include all three through normal CTest registration;
the mismatched-key test uses the OpenSSL command-line tool to generate its key.

## What the existing API looks like

This was written after reading [c2pa-cpp](https://github.com/contentauth/c2pa-cpp)'s
`include/c2pa.hpp` and docs (v0.26.13, a C++17 wrapper over c2pa-rs's C FFI),
and keeps what works in it. What it does today, and where that runs into the
async/threading problem:

* **I/O is a blocking callback.** `Reader(context, format, std::istream&)`
  wraps the stream in a `C2paStream` of C function pointers (`reader`,
  `seeker`, …) that the native library calls *from inside the constructor*,
  on the calling thread, which is parked until the whole read and validation
  finish. The stream must seek and is rewound; it holds a single position, so
  two reads of one asset cannot overlap. Errors cross the boundary as
  `errno` values.
* **Everything else that can wait is blocking too.** `Signer` takes a
  synchronous `SignerFunc`; the HTTP resolver is a synchronous C callback
  (`with_http_resolver`). There is a `FetchingOCSP` progress phase, but you
  cannot answer that fetch asynchronously — only observe it.
* **Cancellation and progress are callbacks.** `with_progress_callback`
  (`bool(phase, step, total)`) and `Context::cancel()` (callable from another
  thread). The docs spell out the cost: the callback must not throw (it is
  caught and turned into a cancellation), and the `Context` must outlive any
  callback that can still fire — hence the `shared_ptr<IContextProvider>`
  overloads and the *deprecated* reference overloads, which "can cause a
  use-after-free".
* **Errors are thread-local.** `C2paException()` fetches the last error from
  the C library (`c2pa_error()`), i.e. from *this thread's* state.
* **Raw handles leak into the public API.** `IContextProvider::c_context()`,
  `Reader::get_api_internal_raw_reader()`, `ContextBuilder::release()`.
* **Thread-safety is mostly implied** (one documented exception, `cancel()`).

None of that is a defect in the wrapper: it is the shape any wrapper over a
*blocking* C API must have. The proposal below changes the C API underneath.

## The answer: yes — and where it stops

A `Session` never performs I/O, never blocks, never spawns, never calls back.
When the engine needs something it parks and reports *requests* (read these
bytes, tell me the time, POST this OCSP request); the host answers in any order
and any subset; `advance()` continues. That is an inversion of control, and in
C++ it buys the following — all demonstrated in `cpp/tests/` and
`examples/parallel.cpp`:

1. **The host picks the concurrency, per call site, with the same engine.**
   `read(session, SyncHost&)` answers one request at a time;
   `PooledHost(host, pool)` runs the very same blocking host's requests
   concurrently; a libuv/asio/io_uring host calls `done(reply)` from its
   completion handler. Nothing in the engine or the ABI changed between them.
   A `SyncHost` need not know it is being parallelized — it only has to be
   thread-safe.
2. **One thread can run many reads.** A `Reading` is a plain object:
   `step()` applies whatever arrived and starts whatever is new, never
   blocking. `one_thread_can_multiplex_many_reads_with_no_threads_at_all`
   interleaves five reads on one thread with a host that has *no* threads.
3. **Coroutines are a natural driver.** `co_read` is `step(); co_await
   reply; repeat`. `spawn()` starts 16 reads from one thread, and they share
   8 I/O threads without any thread blocking inside a c2pa call:

   ```
   $ c2pa_sm_parallel C.jpg 20          # every read takes 20 ms
   serial (blocking)            413 ms   15 reads, up to 1 at once
   thread pool (8)              374 ms   15 reads, up to 3 at once
   coroutine, same pool         372 ms   15 reads, up to 3 at once
   16 assets, 8 I/O threads    1019 ms  240 reads, up to 8 at once
   ```

   (Serial for those 16 assets would be ~6.6 s.)
4. **The session needs no lock even under heavy concurrency.** Completions
   from any thread only *post* to a `Mailbox`; whoever drives the read
   applies them. The one shared structure is that mailbox.
5. **A session may be moved between threads between calls**
   (`a_session_moves_between_threads_between_calls`), and a coroutine is
   resumed by whichever thread completes its request
   (`the_session_migrates_between_threads…`). That is only sound because
   errors are values (`Exception` carries code, name and message captured at
   the failing call), not thread-local state.
6. **Cancellation is destruction.** There is no `cancel()` and no progress
   callback because there is nothing to interrupt: no thread, no lock, no
   pointer into the host. Destroying a `Session`, `Reading` or suspended
   coroutine abandons the read; replies still in flight land in a mailbox that
   outlives the session (the `cancelling_…` tests, run under AddressSanitizer
   in CI). The settings are copied at construction, so there is no `Context`
   to dangle. *Progress* is simply what you can observe between steps.
7. **A finished `Reader` is immutable**, so any number of threads may query it
   with no lock (`Reader` is `Send + Sync` on the Rust side).

**Where it stops — measured, not hoped.** Look at the numbers above: one
read of one asset goes up to only 3 requests at once. `locate` walks the JPEG
segment chain, each header read depending on the last, so most of a read is
inherently serial; only the hash phase fans out, and its width scales with
asset size. The model cannot create parallelism the algorithm lacks. The wins
are: overlap *across* assets (item 3), overlap of the hash chunks and the
OCSP/timestamp round trips on large assets, and never parking a thread on
any of it. Also, `advance()` does the hashing and parsing *inline*, so CPU
work is still on the driver's thread; moving hashing behind a request the
host can run on a pool (or hardware) would be the next step — a change to the
engine, not to this binding.

## What changed from c2pa-cpp, and why

Kept (so a c2pa-cpp user is at home): the `Reader` name and `json()`,
`is_embedded()`, `active_label()`; settings as c2pa-rs JSON; `std::optional`
for "no manifest" (`Reader::from_asset`'s contract); one exception type;
`std::istream` as a host (`IStreamHost`).

| c2pa-cpp | here | Why |
|---|---|---|
| `Reader(context, format, std::istream&)` — constructor reads synchronously | `Session` + a driver; `read(session, host)` is the one-liner | The constructor *is* the blocking call. Making the work a value that is advanced step by step is the point of the model; the one-liner keeps the simple case simple. |
| `C2paStream` callback table, `errno` errors, "must seek" | `ReadRequest{id,start,len}` → `Bytes`, and `Failed{message}` for any request | Plain data both ways: no function pointers across the ABI, no exceptions that must not cross, no stream position to share. Hosts need not seek or be sequential. A host failure is a *value* the engine interprets (fail-open for OCSP, an error for a read). |
| `Context`/`IContextProvider`/`Settings`/`ContextBuilder`, `shared_ptr` lifetimes, deprecated reference overloads | `Session(format, optional<settings_json>)` | Settings are copied at construction; no context object is held, so none can be outlived. This removes the use-after-free class the c2pa-cpp docs warn about. A richer `Settings` type can sit in front of the JSON string without touching the ABI. |
| Progress callback + `Context::cancel()` | Destroy the session; observe between steps | No callback means no "must not throw", no lifetime rule, no cross-thread cancel race. |
| `C2paException()` reads thread-local `c2pa_error()` | `Exception{code(), name(), what()}`, error object returned by value | Required for thread hopping and coroutines; also makes errors inspectable by code (`ErrorCode`) and by c2pa-rs's `Debug` name (`C2pa(UnsupportedType)`). |
| `c_context()`, `get_api_internal_raw_reader()`, `release()` | none | The C handles are an implementation detail; exposing them freezes the ABI. |
| Shared C symbols `c2pa_*` | `c2pa_sm_*`, types `C2paSm*`, namespace `c2pa::sm` | Links into a process beside c2pa-c without collision. |
| C++17 | C++17 core + thread drivers; C++20 only for `c2pa_sm_coro.hpp` | Same floor as c2pa-cpp; coroutines are opt-in. |
| `Reader::json()` may throw, handle may be moved-from | `Reader` is immutable and `const`-everything | Safe concurrent reads without a lock. |

Deliberately *not* done: a `std::future`/`std::async`-only API (it hides the
step boundary that makes cancellation and multiplexing possible; `read_future`
is provided as a convenience over `Reading`, not the model), exceptions inside
the ABI, and a built-in event loop (the bundled thread pools are for tests
and the example; a real application implements `ThreadPool` over its own
executor).

## The ABI

About seventeen small reader functions plus the signing session and buffer-lease
functions, all declared in the generated
[`contentauth_c2pa_c_api.h`](../contentauth-c2pa-c-api/include/contentauth_c2pa_c_api.h)
and documented in [`contentauth-c2pa-c-api`](../contentauth-c2pa-c-api/src/lib.rs):
`session_new/free/advance/request/fulfill/finish`,
`reader_json/validation_state/active_label/is_embedded/free`, `error_code/message/name/free`.
`Reader::validation_state()` returns `ValidationState::{Invalid, Valid, Trusted}`
directly from the report, without parsing JSON. A moved-from reader rejects
that query with `InvalidArgument`; the C accessor reports `UNAVAILABLE` for null.
Rules: nothing blocks, spawns, locks or calls back; errors are values through
an out-parameter; a session is `Send` but not `Sync`; panics become
`C2PA_SM_ERR_PANIC` rather than unwinding into C++; every pointer in a
request borrows from the session until the next call that takes it mutably.
The header is generated by the C API crate's build script (cbindgen); a
mismatch with the C++ wrappers is a compile, link, or test failure. Handles
are tracked by cimpl, so a stale, wrong-type or null handle is rejected rather
than dereferenced.

## Testing

* **Rust** (`cargo test -p contentauth-c2pa-c-api`): the canonical ABI's own
  suite drives it end to end from Rust, plus null/malformed arguments,
  misanswered requests, the OCSP request mapping and authenticated good/revoked
  response fixtures, panics, `Send`/`Sync`, and independent zero-copy
  read/write buffer ownership. The duplicate suite in this crate
  (`cargo test -p contentauth-c2pa-cpp`) is no longer linked by the C++ build and
  is removed with the crate in the final consolidation phase; see the
  [consolidation plan](../docs/c-api-consolidation-plan.md).
* **C** (`c2pa_sm_c_smoke`, test `c_api.c_link_smoke`): a plain C11 program,
  with no C++ wrapper involved, links the canonical library, drives a read
  session by hand over an in-memory asset, and checks owned errors, registry
  format selection and a rejected signing definition.
* **C++** (`ctest`): one C++20 GoogleTest executable, `c2pa_sm_tests`, covers
  core APIs, thread pools, signing, and coroutines. Each test is discovered
  individually by CTest, alongside the existing example tests. The normal build
  also compiles and links `c2pa_sm_cxx17_check`, which checks the public
  non-coroutine headers and representative API usage in explicitly enforced
  C++17 mode, without GoogleTest. It is not a runtime test and is not instrumented
  for coverage. The compiled core remains C++17; only the coroutine library
  and runtime tests use C++20.
  CI runs the discovered tests in parallel and the whole GoogleTest executable
  in one process, plain with coverage (gcovr → Codecov, flag `cpp-binding`),
  under AddressSanitizer and under ThreadSanitizer. Project C++ targets explicitly
  enable `-Wdangling-else` and treat warnings as errors on both macOS and Linux.
  ASan has already earned
  its keep: it caught the C++ wrapper evaluating `check(f(&error), error)`
  in an unspecified order, which leaked every error and replaced its message
  with a placeholder.

GoogleTest is a test-only dependency, never linked into the public libraries.
By default CMake requires an installed GoogleTest >= 1.17 package; set
`GTest_DIR` or `CMAKE_PREFIX_PATH` for an offline or custom installation.
Alternatively, explicitly allow fetching GoogleTest 1.18.0, pinned by SHA-256:

```sh
./test.sh -DC2PA_SM_FETCH_GTEST=ON
```

The fetched source retains its upstream BSD-3-Clause license and is not installed
with the binding. No GoogleTest download is attempted with `BUILD_TESTING=OFF`,
or without the explicit fetch option. `test.sh` always enables testing, including
when its build directory was previously configured with testing disabled.

From this directory, run or filter tests with:

```sh
./build/c2pa_sm_tests
./build/c2pa_sm_tests --gtest_filter='AsyncSigning.*:ThreadPool.*'
ctest --test-dir build --output-on-failure --parallel 2
ctest --test-dir build -R '^cpp\.Coroutines\.' --output-on-failure
cmake --build build --target c2pa_sm_cxx17_check
```

Coverage includes only production headers and implementation sources, not
GoogleTest, fixtures, the compatibility check, or test assertions. Migrating
frameworks does not replace testing uncovered production paths or change the
Codecov thresholds.

Linux tests use executable-only linker wrapping to inject POSIX read/write
interruptions, short transfers, invalid metadata, and sync failures. Faults are
thread-local and scoped; production libraries keep calling the real system
calls. The coroutine death test checks the non-throwing `spawn` completion
contract in a separate process and flushes coverage before its expected exit.
Custom LLVM-instrumented builds can also define `C2PA_SM_LLVM_PROFILE` for the
test runner to flush the child process's profile.

## Signing contract

Phase 1 supplies C++17 value types in `include/contentauth/c2pa_sm_sign.hpp`.
Phase 2 supplies the signing C ABI, now the canonical
[`contentauth_c2pa_c_api.h`](../contentauth-c2pa-c-api/include/contentauth_c2pa_c_api.h),
implemented in [`contentauth-c2pa-c-api`](../contentauth-c2pa-c-api/src/signing.rs)
over cimpl 0.4.1. Phase 3 adds the move-only
C++17 `BuildSession`, blocking `build_and_sign`, and memory, seekable-stream,
and POSIX atomic-file host declarations in the same C++ header. Their
implementations live in `cpp/src/sign.cpp`; signing callers must link the
`c2pa_sm_cpp` CMake target, not just the Rust static library. Both Rust and C++ tests
sign and read back the baseline JPEG as `Trusted`, with an explicit trust
anchor and clock. Existing reader APIs are unchanged.

### Inputs and baseline

`BuildSettings` owns the definition JSON, format (default `image/jpeg`),
algorithm (default `es256`), and DER certificate chain, leaf first. The first
end-to-end milestone supports JPEG + ES256. The definition uses the existing
`contentauth-c2pa-sign-baseline::Definition`: the host supplies `instance_id`
and `label` (there is no engine RNG), exactly one `claim_generator_info`,
and any supported assertions. The acceptance fixture includes a title and
one `c2pa.actions.v2` assertion containing `c2pa.created`. Unknown definition
fields fail rather than being ignored. A private key is never an input.

The bridge delegates to `contentauth-c2pa-session-bridge::build::BuildSessionBridge`,
which is already a host-agnostic, synchronous wrapper over the file builder.
Do not add another signing engine or an I/O dependency to this binding.

### Session and host

The move-only `BuildSession(BuildSettings)` copies inputs into Rust.
`advance()` returns completion or newly issued `BuildRequest` values;
an empty pending batch does not mean completion. `fulfill(id, BuildReply)`
accepts any subset of outstanding replies in any order. Unknown IDs,
duplicate replies, and wrong reply kinds are errors. `finish()` consumes a
completed session and returns `SignReport`; premature finish is an error.
Call it as `std::move(session).finish()`: even a failed finish consumes the
handle. Moved-from operations throw `Exception` rather than dereferencing it.
Neither a session nor its ABI starts host work or invokes host callbacks.

| Request | Required reply | Host obligation |
|---|---|---|
| `BuildReadRequest` | `CompletedRead` | Fill its Rust-owned `destination` with exactly `len` bytes at `start` of `stream`, then seal it |
| `BuildLengthRequest` | `Length` | Return the selected stream's length |
| `WriteRequest` | `Written` | Write all `bytes` at `offset`; acknowledge only once subsequent reads see them |
| `SignRequest` | `Signature` | Sign the complete COSE `Sig_structure` in `data` using `algorithm`; ES256 returns 64-byte raw `r \|\| s`, not DER |
| `TimestampRequest` | `TimestampResponse` | POST `body` to `url` as `application/timestamp-query`; return the unmodified DER `TimeStampResp` |

`Failed` is valid for every request and fails the build. A host must finish
partial reads/writes itself or report failure, never acknowledge a short
operation as successful. `BuildReply` reuses the reader's `Length` and
`Failed`; read replies instead own a move-only `CompletedRead`.
`BuildRequest` and `BuildReply` are move-only. Read destinations and write
payloads own independent Rust buffer leases, not borrows into the session.
Sign and timestamp payloads still own their C++ strings and vectors.

### Zero-copy signing reads and writes

`BuildSession::advance()` acquires a Rust-owned `ReadBuffer` for each new
read. Its `writable()` method returns `MutableBytes { data, size }`.
`SyncBuildHost::read_into(stream, start, destination)` fills the entire
destination or throws. The file host uses `pread` directly into this
storage; the stream host reads into it, and the memory host copies from
its asset into it. `answer` seals the filled buffer and returns a
`CompletedRead`; `fulfill(id, std::move(reply))` moves that allocation into
the existing Rust byte reply without copying its contents.

The signing C ABI exposes `c2pa_sm_build_read_acquire`,
`c2pa_sm_read_seal`, `c2pa_sm_build_fulfill_read`, and independent free
functions for writable and completed buffers. All handles are cimpl-tracked.
Sealing validates the exact byte count. Fulfillment validates the session,
request ID, and lease identity before transferring storage. Invalid
operations preserve caller ownership; successful transfers null the input
handle. A read may acquire only one lease; another byte reply cannot bypass
it. The original copying C byte-reply API remains available for reads that
have not acquired a lease.

Read storage survives session destruction. Async hosts must retain each
writable lease until I/O has stopped, then seal and move its completion
into `done`. Failure also requires stopping I/O first; it does not free an
outstanding lease. Cancelled mailboxes discard late completed buffers
through RAII. Never access a saved writable pointer after sealing or
freeing its lease. Dropping a lease does not answer its pending request.

Each `WriteRequest::bytes` owns a move-only `WriteBuffer`. Its `view()`
returns `ConstBytes { const uint8_t *data, size_t size }`;
`SyncBuildHost::write(stream, offset, view)` writes directly from those
Rust-owned immutable bytes. The file builder, session bridge, and ABI
share `bytes::Bytes` ownership without copying the payload.
The C ABI exposes `c2pa_sm_build_write_acquire` and
`c2pa_sm_write_buffer_free`; multiple immutable leases are allowed.

Write storage survives acknowledgment and session destruction. Async hosts
must retain the owning request or buffer until I/O actually stops, including
after cancellation. A pointer/length view alone does not retain storage.
Releasing the lease and answering `Written` are independent operations.
Sign/signature/timestamp payload copies remain outside this change, and
memory-host reads/writes still copy as their actual I/O operation.
No I/O or networking moves into Rust. See the
[zero-copy walkthrough](../docs/walkthrough/10-zerocopy.md) for ownership
rules and verification of both implemented lease phases.

`BuildStream::Source` is read-only. `BuildStream::Output` must start empty,
must not alias the source, and must support random-access writes and reads:
the builder hashes output bytes after writing them. A stream-level failure
or cancellation can leave partial output; rollback is not a session promise.
The file convenience driver uses an exclusively created temporary file beside
the destination and publishes it only on success, cleaning it up on failure.
`SignReport` contains embedded manifest bytes and all hard-binding
`exclusions`, not the output asset itself.

An optional `tsa_url` in the definition requests timestamping. The blocking
driver forwards the URL and DER request to the host's timestamp callback.
Rust constructs the RFC 3161 request and unwraps the response. No configured
TSA means no timestamp request; a configured TSA that is unavailable, refuses,
or returns malformed data must fail rather than produce untimestamped output.

### Async C++ signing

Phase 4 adds `c2pa_sm_sign_async.hpp`, compiled in `cpp/src/sign_async.cpp`.
`Building` owns a single-driver session; `AsyncBuildHost::start` owns requests,
and callbacks only post to `BuildMailbox`. `step` never waits; use its mailbox
wait/waker or `build_parallel`. `build_future` owns its driver thread and host;
dropping the future joins. `Building::wait()` waits for started requests' first
completion callbacks to quiesce, even after a build error. `build_parallel`
and `build_future` drain those callbacks before returning or throwing, keeping
borrowed hosts alive through accepted work. Never call `wait()` from that
operation's completion callback or mailbox waker. A host that never completes
a request can still block these drivers indefinitely.
Cancellation discards late replies, not host work.
`PooledBuildHost` serializes host operations, including signer/TSA callbacks,
through one FIFO drain task per adapter, without parking other pool workers
or holding a mutex during user code. See the header for lifetime boundaries.

Compiled implementations share the internal C++17 `detail::make_scope_exit`
helper in `cpp/include/scope_exit.hpp` for cleanup on normal exit or exception
unwinding. Each guard owns a non-throwing callable, runs it once, and is neither
copyable nor movable. The header is private, not part of the public binding API.

### Blocking C++ signing

`SyncBuildHost` defines `read(stream, start, len)`, `length(stream)`, and
`write(stream, offset, bytes)`. The blocking driver answers every request
without spawning or blocking inside the session. Host exceptions, including
non-standard exceptions and callback failures, become `Failed` replies. A
short read also becomes `Failed`; a custom write method must finish the entire
write before returning. An empty pending batch is not a completed build.

`BuildSigner` accepts `(algorithm, data)` and returns the signature bytes.
`BuildTimestamp` accepts `(url, body)` and returns the entire DER response.
These are `std::function` callbacks owned by the host. Missing callbacks fail
only when requested. There is no default signer or HTTP client.

```cpp
#include <contentauth/c2pa_sm_sign.hpp>

c2pa::sm::BuildSettings settings;
settings.definition_json = definition_json;
settings.certificates = {leaf_certificate_der};
c2pa::sm::MemoryBuildHost host(source_jpeg, signer, timestamp_transport);
auto report = c2pa::sm::build_and_sign(c2pa::sm::BuildSession(settings), host);
const auto &signed_jpeg = host.output();
```

The definition must include the baseline's instance ID, label, generator and
assertion. The signer owns the private key and signs the complete COSE input;
ES256 returns raw `r || s`. Omit `timestamp_transport` if the definition has no
`tsa_url`. `report` owns its manifest and exclusion ranges independently of
the session and ABI report handle.

`IOStreamBuildHost(source, output, signer, timestamp_transport)` takes a
seekable `std::istream` and an initially empty `std::iostream`. Their stream
buffers must differ; callers must also avoid separate buffers referring to
the same underlying asset. Output is flushed before a write is acknowledged
and remains readable for hard-binding hashing. Seek, short-I/O, flush and
stream-state failures fail the build. Memory and stream hosts do not roll back
partial output after failure.

On POSIX systems, `build_and_sign_file(settings, source_path, destination_path,
signer, timestamp_transport)` uses `FileBuildHost`: `mkstemp` exclusively creates
an unpredictable sibling temporary, and `pread`/`pwrite` retain that descriptor
without reopening its pathname. Writes retry interrupted or partial system
calls. Only a completed build and successful `fsync` permit atomic `rename`.
The published output deliberately retains `mkstemp`'s private mode **0600**,
regardless of the source's mode, a replaced destination's mode, or the umask.
Callers wanting broader access must explicitly change permissions after success.
Failures, including rename failures, remove the temporary and preserve an
existing destination. A destination symlink is replaced, not followed. As with
ordinary atomic-replacement APIs, the destination directory must be controlled
by the caller. The parent directory is not `fsync`ed: publication is atomic,
but the rename is not guaranteed durable across a system crash. This is not
a hostile-directory promise.
The file helper is intentionally unavailable on non-POSIX platforms rather
than offering a predictable or symlink-following temporary fallback. Use the
portable stream host with a platform-owned safe publication strategy there.

The C++ tests use OpenSSL Crypto for the fixture ES256 signer, and the signing
example uses it for its host-owned callback. CMake therefore requires its
development package. Neither the library's production hosts nor its public
signing headers depend on OpenSSL.

### FFI, errors, and concurrency

The new ABI uses [cimpl](https://github.com/contentauth/cimpl) 0.4.1 tracked
allocations, exclusive session checkout, shared report checkout, and typed
consuming free operations. Null frees are no-ops; wrong, stale, and busy
handles are rejected. The reader ABI retains its existing ownership model and
adds the typed validation-state accessor described above. The new
functions retain the `c2pa_sm_*` namespace and the existing panic-catching,
owned-error boundary. cimpl's fallible Rust helpers return errors directly;
the bridge does not use its TLS last-error macros. This preserves per-call
errors that can cross threads independently of the session. The existing
error allocation/access/free functions are reused, not migrated to cimpl.

`C2PA_SM_ERR_BUILD` distinguishes engine/host build failures from read errors.
Signing values are grouped into `C2paSmBuildErrorCode`,
`C2paSmBuildRequestKind`, `C2paSmBuildReplyKind`, and `C2paSmBuildStream`
enums. Their existing C names and numeric values are preserved. ABI fields
remain integers so unknown foreign reply kinds can be rejected normally,
rather than creating an invalid Rust enum discriminant at the boundary.
Invalid definitions, inputs, handles, IDs, and reply kinds use
`C2PA_SM_ERR_INVALID_ARGUMENT`; unsupported formats use the existing
unsupported-type code. All fallible signing operations return a status and
an optional owned `C2paSmError` through an out-parameter. A valid session is
consumed by `finish` even on failure (including null report output); invalid
or busy handles are rejected without consuming another operation's handle.

The ABI consists of `c2pa_sm_build_session_new/advance/request/fulfill/finish/free`
and `c2pa_sm_sign_report_view/free`. `advance` returns completion and the count
of new requests. Raw request views borrow session storage; callers must copy
needed metadata and unleased payloads before advancing or fulfilling.
Acquired read/write buffers instead own independent storage. Reports are
immutable, independently owned handles; report views borrow their storage
until the report is freed.
Do not free a session/report concurrently with use of its borrowed storage.

The canonical header is regenerated by `contentauth-c2pa-c-api`'s build script
whenever cargo builds that crate, which CMake does; no separate generator step
is needed. It is checked as C11 and C++17 by that crate's `tests/check-features.sh`,
and the C++ and C smoke tests here link its real symbols. Native and both Wasm
targets are checked with the pinned cimpl release. The engine remains
sans-I/O; cimpl's allocation registry adds synchronization at the FFI boundary.

A session has one driver at a time and can move between threads between calls.
Later async completions post owned replies into a mailbox; only the driver
calls `advance`/`fulfill`. Destroying the operation abandons the session, not
host I/O already in flight. Mailboxes must outlive outstanding completions,
and hosts must outlive their own work. The engine remains sans-I/O; cimpl's
allocation registry must not be mistaken for a guarantee of a lock-free FFI.

### Phase 1 completion gate

* The value types compile as C++17 and their ownership is tested in `cxx17`.
* The baseline inputs, stream semantics, request/reply mapping, lifecycle,
  error ownership, and cancellation responsibilities are explicit above.
* The cimpl approach is documented, with version-specific verification
  reserved for Phase 2; no reader ABI migration is included.
* Stop for approval before adding the Rust signing dependency or ABI.

### Phase 2 completion gate

* The C ABI drives the baseline JPEG/ES256 build and the reader validates its
  output as `Trusted`, with the expected title and assertion.
* Tests cover every request/reply mapping, host failures, timestamp response
  embedding/refusal/malformed data, invalid inputs, duplicate IDs, premature
  finish, stale/wrong/busy handles, and cross-thread handles and owned errors.
* The timestamp success fixture is a synthetic opaque token: this checks
  transport/embedding, not cryptographic TSA validation.
* Generated C declarations compile and link; Rust tests, strict lint/format,
  docs, Wasm targets, dependency policy, and focused coverage are checked.
* Stop for approval before implementing the C++ `BuildSession` or blocking driver.

### Phase 3 completion gate

* Move-only C++17 session ownership, consumed error finishes, copied settings,
  request batches and reports, invalid/duplicate replies and moved-from use
  are covered by the focused C++ tests.
* Blocking memory, seekable-stream and POSIX-file builds read back as `Trusted`;
  source/output independence, short/failing I/O, throwing/missing callbacks,
  timestamp refusal/malformed replies and file rollback/cleanup are tested.
* The synthetic granted timestamp checks DER response transport and embedding
  only, not cryptographic TSA validity. Real HTTP and signing stay host-owned.
* C++17 and C++20 compilation and focused CTest entries pass. Full five-entry
  CTest, coverage and sanitizer acceptance remain required before submission.
* Phase 4 adds async/pool/future signing; coroutine signing is Phase 5.

### Phase 4 completion gate

* Queued single-thread hosts and pooled memory/stream hosts sign baseline JPEGs
  that read back as `Trusted`; callbacks own requests and only enqueue replies.
* Tests cover synchronous and out-of-order delivery, overlapping/reentrant driver
  rejection, waker registration races, terminal protocol errors, cancellation,
  late callbacks, and host/pool submission failures.
* Pooled access to mutable hosts is serialized. Futures retain the host and
  propagate errors; destroying the last future waits for its driver thread.
* C++17/C++20 builds, all five CTest entries, coverage, ASan and TSan are checked.
* Phase 5 adds the opt-in C++20 coroutine signing driver below.

### Phase 5 completion gate

Include `contentauth/c2pa_sm_sign_coro.hpp` and link `c2pa_sm_coro`, which
transitively links `c2pa_sm_cpp`. Only consumers of this new target require
C++20; `c2pa_sm_cpp` and its existing consumers remain C++17.

```cpp
Task<SignReport> sign(BuildSession session, AsyncBuildHost &host) {
    co_return co_await co_build_and_sign(std::move(session), host);
}
```

* The compiled implementation is `cpp/src/sign_coro.cpp`. It reuses `Building`,
  `BuildMailbox`, `Task<T>` and `spawn`, without a scheduler or worker of its own.
  `.get()` blocks its caller; `co_await` and `spawn` suspend at host boundaries.
* Replies resume on their delivery thread. Inline replies are drained without
  recursive resumption; atomic mailbox registration prevents lost wakeups.
* Destroying a suspended `Task` cancels it and synchronizes with active
  callback-driven resumption, including nested read/signing Tasks. Access to
  the `Task` object itself must still be externally serialized. Foreign
  coroutine owners must serialize destruction of their own frames with
  resumption. Cancellation does not drain host I/O: hosts must outlive all
  started work, including work remaining after task destruction.
* Focused tests cover Trusted JPEG/ES256, owned reports, queued interleaving,
  reverse-order and inline replies, late callbacks, pooled thread migration,
  get/await/spawn, host exceptions, invalid replies and timestamp failure paths.
  The synthetic granted TSA response proves transport and embedding only,
  not cryptographic timestamp validity. Keys and real HTTP remain host-owned.
* Regression tests race Task destruction with cross-thread replies, verify
  parallel/future error paths drain accepted work, and check FIFO ordering
  without starving unrelated pool tasks. The full nine-entry CTest suite
  passes in normal, ASan and TSan builds.
* Phase 5 added no new crypto or ABI.

### Phase 6 hardening and integration

The atomic-file tests now check that missing, throwing, malformed and refusing
TSA responses preserve existing destinations, never publish a new destination,
and remove temporary files. Same-path signing is tested for successful Trusted
replacement and preservation on signing failure. The public-header signing
example exercises file signing and read-back as an actual executable.

The CI C++ matrix runs every CTest entry in coverage, ASan and TSan builds,
including the new example; it installs OpenSSL explicitly and measures library
headers and compiled sources, not demo or test helpers. The Rust static library
is not sanitizer-instrumented by that C++ matrix. Local acceptance passed all
seven CTest entries in coverage, ASan and TSan builds, plus workflow YAML and
runner syntax checks. The three signing implementation sources cover 435/442
executable lines (98.42%) and 348/553 branch outcomes (62.93%); examples and
test helpers are not included in those figures. Remote CI must still run before
merge. Real private keys, HTTP and trust policy stay with the host. The coroutine
destruction boundaries are strengthened by the regression fixes documented above.

Additional regression tests exercise throwing mailbox wakers, cancellation
waking a blocked waiter and discarding late replies, and pooled hosts continuing
after standard and nonstandard I/O exceptions. Conversion tests verify that
request payloads are owned copies, including embedded zero bytes. A file-host
test truncates a private test source immediately after its length is checked,
then requires an explicit read failure and temporary-output cleanup.

## Not covered

* No production key or HTTP provider is included. Atomic file
  signing currently requires POSIX; memory and stream hosts are portable C++17.
* Resources (`get_resource`), `detailed_json`, `crjson`, fragments, remote
  manifests, and the OCSP request path in the C++
  tests (the fixtures name no responder; it is covered from Rust). The
  canonical library selects JPEG and TIFF/BigTIFF/DNG, but the C++ tests
  exercise JPEG only.
* Packaging (CMake `install`/`find_package`, vcpkg, Conan).
