# contentauth-c2pa-cpp

An experimental C++ binding for the sans-I/O C2PA reader, written to answer
one question: **can the session model express asynchronous and threaded
behavior that a callback-based C++ API cannot?**

It is a Rust static library behind a small C ABI (`src/lib.rs`,
`include/contentauth_c2pa_sm.h`) and **C++** on top (`include/contentauth/`),
header-only except for the thread pools (`cpp/src/`, built as `c2pa_sm_cpp`):

| Header | Standard | Provides |
|---|---|---|
| `c2pa_sm.hpp` | C++17 | `Session`, `Reader`, the request/reply vocabulary, `Exception`, the blocking driver `read()`, hosts for memory / `std::istream` / files |
| `c2pa_sm_async.hpp` | C++17 | `AsyncHost`, `Reading`, `Mailbox`, `read_parallel`, `read_future`, `PooledHost` |
| `thread_pool.hpp` | C++17 | the `ThreadPool` interface, `make_simple_thread_pool`, and on Apple platforms `make_apple_thread_pool` (GCD) |
| `c2pa_sm_coro.hpp` | C++20 | `Task`, `co_read`, `spawn` |

```cpp
#include "contentauth/c2pa_sm.hpp"

c2pa::sm::FileHost host("photo.jpg");
auto reader = c2pa::sm::read(c2pa::sm::Session("image/jpeg"), host);
if (reader) std::cout << reader->json();   // nullopt: no Content Credentials
```

Read side only at runtime; the signing value types and proposed contract are
described in [Signing contract](#signing-contract). Build with `./build.sh`, or
build and test with
`cmake -S . -B build && cmake --build build && ctest --test-dir build`
(needs cargo, CMake ≥ 3.16, a C++17 compiler; the coroutine pieces need C++20).

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

About seventeen small functions (header: `include/contentauth_c2pa_sm.h`,
documentation: `src/lib.rs`): `session_new/free/advance/request/fulfill/finish`,
`reader_json/active_label/is_embedded/free`, `error_code/message/name/free`.
Rules: nothing blocks, spawns, locks or calls back; errors are values through
an out-parameter; a session is `Send` but not `Sync`; panics become
`C2PA_SM_ERR_PANIC` rather than unwinding into C++; every pointer in a
request borrows from the session until the next call that takes it mutably.
The header is hand-written (a dozen declarations); the C++ tests link against
the real library, so drift is a link or test failure.

## Testing

* **Rust** (`cargo test -p contentauth-c2pa-cpp`): drives the ABI end to end
  from Rust, plus null/malformed arguments, misanswered requests, the OCSP
  request mapping (which no fixture here provokes), panics and `Send`/`Sync`.
* **C++** (`ctest`): a dependency-free harness; C++17 and C++20 binaries.
  CI runs them plain with coverage (gcovr → Codecov, flag `cpp-binding`),
  under AddressSanitizer and under ThreadSanitizer. ASan has already earned
  its keep: it caught the C++ wrapper evaluating `check(f(&error), error)`
  in an unspecified order, which leaked every error and replaced its message
  with a placeholder.

## Signing contract

Phase 1 supplies C++17 value types in `include/contentauth/c2pa_sm_sign.hpp`.
There is no signing ABI, `BuildSession`, or signing driver yet. The following
contract guides those later phases; it does not describe available functions.

### Inputs and baseline

`BuildSettings` owns the definition JSON, format (default `image/jpeg`),
algorithm (default `es256`), and DER certificate chain, leaf first. The first
end-to-end milestone supports JPEG + ES256. The definition uses the existing
`contentauth-c2pa-sign-baseline::Definition`: the host supplies `instance_id`
and `label` (there is no engine RNG), exactly one `claim_generator_info`,
and any supported assertions. The acceptance fixture includes a title and
one `c2pa.actions.v2` assertion containing `c2pa.created`. Unknown definition
fields fail rather than being ignored. A private key is never an input.

The bridge will delegate to `contentauth-c2pa-node-compat-sign::NodeBuildSession`,
which is already a host-agnostic, synchronous wrapper over the file builder.
Do not add another signing engine or an I/O dependency to this binding.

### Session and host

The proposed move-only `BuildSession(BuildSettings)` copies inputs into Rust.
`advance()` returns completion or newly issued `BuildRequest` values;
an empty pending batch does not mean completion. `fulfill(id, BuildReply)`
accepts any subset of outstanding replies in any order. Unknown IDs,
duplicate replies, and wrong reply kinds are errors. `finish()` consumes a
completed session and returns `SignReport`; premature finish is an error.
Neither a session nor its ABI starts host work or invokes host callbacks.

| Request | Required reply | Host obligation |
|---|---|---|
| `BuildReadRequest` | `Bytes` | Read exactly `len` bytes at `start` of `stream` |
| `BuildLengthRequest` | `Length` | Return the selected stream's length |
| `WriteRequest` | `Written` | Write all `bytes` at `offset`; acknowledge only once subsequent reads see them |
| `SignRequest` | `Signature` | Sign the complete COSE `Sig_structure` in `data` using `algorithm`; ES256 returns 64-byte raw `r \|\| s`, not DER |
| `TimestampRequest` | `TimestampResponse` | POST `body` to `url` as `application/timestamp-query`; return the unmodified DER `TimeStampResp` |

`Failed` is valid for every request and fails the build. A host must finish
partial reads/writes itself or report failure, never acknowledge a short
operation as successful. `BuildReply` reuses the reader's `Bytes`, `Length`,
and `Failed`; signing has its own request variant because it has two streams.
All C++ payloads own their strings and bytes, not pointers into the session.

`BuildStream::Source` is read-only. `BuildStream::Output` must start empty,
must not alias the source, and must support random-access writes and reads:
the builder hashes output bytes after writing them. A stream-level failure
or cancellation can leave partial output; rollback is not a session promise.
A later file convenience driver should use an exclusively created temporary
file beside the destination and publish it only on success, cleaning it up
on failure. `SignReport` contains embedded manifest bytes and all hard-binding
`exclusions`, not the output asset itself.

An optional `tsa_url` in the definition requests timestamping. The request
and reply types are defined now; the host driver comes in a later phase.
Rust constructs the RFC 3161 request and unwraps the response. No configured
TSA means no timestamp request; a configured TSA that is unavailable, refuses,
or returns malformed data must fail rather than produce untimestamped output.

### FFI, errors, and concurrency

New FFI work must use [cimpl](https://github.com/contentauth/cimpl), not copy
the existing handwritten reader bridge. Its documented tracked allocations,
typed pointer validation, and namespace-safe free wrappers fit opaque build
handles and owned results. The signing API must retain `c2pa_sm_*` names,
validate foreign inputs, and prevent Rust panics from unwinding into C++.

cimpl's documented error macros use last-error state. That must not become
the C++ error contract: each failing bridge operation must capture its error
on the same thread, before another call, and return an owned error through
an out-parameter. Extend the existing error vocabulary for build failures
rather than reporting them as read errors. Verify the selected cimpl version's
tracking/free semantics, generated header, panic behavior, and supported
Rust/Wasm targets with a focused bridge test in Phase 2 before building on it.
No cimpl dependency is selected or added in Phase 1.

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

## Not covered

* **Writing.** `BuilderSession`'s `Sign` and `Timestamp` requests are the
  strongest case for this model (an async KMS/HSM, a TSA over HTTP, without
  parking a thread) and are the obvious next addition: a `NodeBuildSession`
  already exists in `contentauth-c2pa-node-compat-sign` to wrap the same way.
* Resources (`get_resource`), `detailed_json`, `crjson`, fragments, remote
  manifests, formats other than JPEG, and the OCSP request path in the C++
  tests (the fixtures name no responder; it is covered from Rust).
* Packaging (CMake `install`/`find_package`, vcpkg, Conan) and generating the
  C header with cbindgen.
