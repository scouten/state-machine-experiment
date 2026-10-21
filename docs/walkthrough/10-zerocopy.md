# Zero-copy buffers across the Rust/C++ boundary

> **Status: phases 1 and 2 implemented.** Signing reads use independent
> Rust-owned writable leases; writes use immutable shared leases.
> C++ retains all I/O and networking.

## Implementation phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Independent writable read leases, C ABI ownership transfer, C++ `read_into`, blocking/pooled/coroutine drivers, and lifecycle tests | Implemented |
| 2 | Immutable write leases and shared payload storage through forwarding layers | Implemented |

Phase 1 targets the signing workflow's read replies, including output reads
used for hashing. Phase 2 removes the Rust-to-C++ write-payload copy and
reuses shared storage through the Rust forwarding layers. Neither phase
changes reader/validator bindings or transfers I/O to Rust.

## Goal

Keep all file I/O and networking in the C++ host while removing additional
application-level buffer copies across the ABI. Rust allocates storage;
C++ fills it; ownership returns to Rust without copying the bytes.

Buffer allocation is not I/O. The host still decides whether to use blocking
reads, asynchronous I/O, a network transport, or a cache. The sessions remain
synchronous, sans-I/O state machines.

Here, "zero-copy" means avoiding the extra application-level payload copy,
not eliminating the operating system's file-read copy.

Read leases move a `Vec<u8>` into the session bridge; the bridge converts it
to the engine's immutable `bytes::Bytes` without copying its payload.
Writes retain that shared storage through an independent lease.

## Previous read path

Before phase 1, the C++ host read file bytes into a `std::vector<uint8_t>`
and passed its pointer and length through the C ABI. Rust then allocated
a `Vec<u8>` and copied the bytes with `.to_vec()` before accepting the
reply. That copying C reply API remains available for reads that have
not acquired a lease; the C++ signing hosts now use leases.

```text
File -> C++ vector -> copy into Rust vector -> Rust hasher
```

The relevant implementation points are:

* [`FileBuildHost::read_into`](../../contentauth-c2pa-cpp/cpp/src/sign.cpp):
  now reads directly into the Rust-owned destination.
* [`BuildSession::fulfill`](../../contentauth-c2pa-cpp/cpp/src/sign.cpp):
  now transfers a completed lease for read replies.
* [`reply_value`](../../contentauth-c2pa-cpp/src/signing.rs):
  still copies incoming bytes on the unleased C reply path.
* [`HashStream`](../../contentauth-c2pa-builder/src/hash_stream.rs):
  consumes owned chunks and passes borrowed slices to the hasher.

Hashing uses 64 KiB chunks with up to eight in flight. Chunking bounds
payload memory, but does not eliminate the boundary copy.

## Implemented read-buffer lifecycle

```text
Rust session issues Read(id, stream, offset, length)
                         |
C++ acquires a buffer lease for that request
                         |
Rust allocates stable storage, independent of session lifetime
                         |
C++ performs I/O directly into the writable pointer
                         |
C++ seals the lease after I/O has stopped accessing it
                         |
C++ queues the completed buffer in the existing mailbox
                         |
Driver fulfills the request, moving the Vec into Rust
                         |
Rust hashes the same allocation
```

The buffer is independently owned, not a borrow into the session.
Advancing or destroying the session must not invalidate a buffer that an
I/O operation is still using.

## C ABI

The signing ABI exposes the following ownership transitions (see the
[generated header](../../contentauth-c2pa-c-api/include/contentauth_c2pa_c_api.h)
for the authoritative declarations):

```c
typedef struct C2paSmReadBuffer C2paSmReadBuffer;
typedef struct C2paSmCompletedRead C2paSmCompletedRead;

typedef struct {
    uint8_t *data;
    size_t len;
} C2paSmMutableBytes;

/* One writable lease per outstanding read request. */
int c2pa_sm_build_read_acquire(
    C2paSmBuildSession *session,
    uint64_t request_id,
    C2paSmReadBuffer **out_buffer,
    C2paSmMutableBytes *out_bytes,
    C2paSmError **out_error);

/* Ends writable access; requires exactly the requested byte count. */
int c2pa_sm_read_seal(
    C2paSmReadBuffer **buffer,
    size_t bytes_read,
    C2paSmCompletedRead **out_completed,
    C2paSmError **out_error);

/* Moves the completed allocation into the session's byte reply. */
int c2pa_sm_build_fulfill_read(
    C2paSmBuildSession *session,
    uint64_t request_id,
    C2paSmCompletedRead **completed,
    C2paSmError **out_error);

/* Release abandoned storage, independent of session lifetime. */
int c2pa_sm_read_buffer_free(
    C2paSmReadBuffer **buffer,
    C2paSmError **out_error);

int c2pa_sm_completed_read_free(
    C2paSmCompletedRead **completed,
    C2paSmError **out_error);
```

Use cimpl-tracked handles rather than hand-rolled pointer ownership.
Each buffer carries an internal session identity and request ID.
Fulfillment validates both, so a buffer cannot satisfy a different
session's request. Session identity must not rely on a reusable session
address alone.

Separating **seal** from **fulfill** is deliberate:

* Worker threads can seal completed reads without accessing the session.
* Only the driver thread fulfills requests.
* The mailbox owns the completed buffer while delivery is pending.
* Dropping a late reply after cancellation frees its allocation safely.

This uses the worker-completion and mailbox model in
[`sign_async.cpp`](../../contentauth-c2pa-cpp/cpp/src/sign_async.cpp).

## C++ interface

Replace vector-returning reads with reads into supplied storage:

```cpp
struct MutableBytes {
    uint8_t *data;
    size_t size;
};

// Read exactly destination.size bytes or report failure.
virtual void read_into(
    BuildStream stream,
    uint64_t offset,
    MutableBytes destination) = 0;
```

Wrap ABI handles in move-only RAII classes. Conceptually:

```cpp
class ReadBuffer {
public:
    MutableBytes writable();
    CompletedRead seal(size_t bytes_read) &&;
    // Destructor releases an abandoned buffer.
};

class CompletedRead {
    // Owns immutable completed storage until fulfilled or discarded.
};

struct BuildReadRequest {
    uint64_t id;
    BuildStream stream;
    uint64_t start;
    ReadBuffer destination;
};
```

Read replies carry a move-only `CompletedRead` instead of `Bytes`.
The blocking host fills and seals the destination:

```cpp
auto destination = request.destination.writable();
host.read_into(request.stream, request.start, destination);
return std::move(request.destination).seal(destination.size);
```

The POSIX host keeps its partial-read and `EINTR` handling, but reads into
the supplied pointer instead of allocating a C++ vector.

The blocking, pooled, and coroutine drivers move requests and
completed replies without cloning their storage. The integration is in
[`sign_async.cpp`](../../contentauth-c2pa-cpp/cpp/src/sign_async.cpp) and
[`sign_coro.cpp`](../../contentauth-c2pa-cpp/cpp/src/sign_coro.cpp) alongside
the blocking driver.

A memory-backed host still copies existing asset bytes into the supplied
destination: that is its read operation. The design removes the
subsequent ABI copy, not every possible host-side copy.

## Rust implementation

A writable lease owns its allocation:

```rust
struct ReadBuffer {
    session_identity: SessionIdentity,
    request_id: u64,
    bytes: Vec<u8>,
}
```

The implementation uses a private `Arc<()>` for session identity and
another for lease identity, rather than adding a public engine type.
Outstanding leases keep these identities alive, so a reusable session
address cannot impersonate the original session. The vector is allocated
to its final length before exposing its pointer and never resized while
checked out.

After sealing and validating fulfillment, move the allocation through
the existing reply types:

```text
ReadBuffer's Vec
    -> Reply::Bytes(vec)
    -> FileBuilderReply::Bytes(Bytes::from(vec))
    -> BuilderHostReply::AssetBytes(bytes)
    -> hasher.update(&bytes)
```

These are ownership moves, not payload copies. The existing forwarding in
[`session.rs`](../../contentauth-c2pa-file-builder/src/session.rs) already
moves byte replies, and
[`HashStream`](../../contentauth-c2pa-builder/src/hash_stream.rs) hashes
borrowed slices.

The new lease fulfillment path bypasses the read-reply `.to_vec()` in
[`reply_value`](../../contentauth-c2pa-cpp/src/signing.rs), without
requiring a new byte-storage abstraction throughout the engine.

Phase 1 uses initialized storage with fallible allocation and explicit
error propagation. Zero-initialization is memory work, but not a
C++-to-Rust payload copy. Uninitialized destinations are a separate
optimization requiring a carefully reviewed initialization contract.

Do not adopt a `std::vector` pointer using `Vec::from_raw_parts`:
the allocation and deallocation contracts need not match.

## Ownership, concurrency, and cancellation

| State | Owner | Allowed access |
|---|---|---|
| Writable | C++ request or I/O operation | Exclusive writes through the exposed pointer |
| Completed | Reply or mailbox | No further writes |
| Accepted | Rust session | Consume and hash bytes |
| Abandoned | Lease released | Storage freed, only after I/O stops |

Required rules:

1. **One writable lease per request.** Reject duplicate acquisition and
   attempts to fulfill the same request through a different reply path
   while its lease is outstanding.
2. **Serialize session calls.** Independent buffers may be filled
   concurrently, and reads may complete out of order.
3. **Keep storage stable.** No Rust reference into the bytes survives
   checkout; session mutation cannot invalidate outstanding buffers.
4. **Validate byte counts.** Short reads fail explicitly. Never hash a
   filled prefix followed by unused bytes.
5. **Synchronize completion.** Host writes must happen before the driver
   consumes the buffer. The existing mailbox mutex provides the
   cross-thread handoff.
6. **Cancellation is not immediate deallocation.** The worker retains
   its lease until the underlying I/O has stopped accessing memory.
   Failure completion has the same requirement.
7. **Separate buffer and session lifetimes.** Session destruction does
   not free checked-out leases. Late completions can be discarded
   without accessing the destroyed session.
8. **Make abandonment explicit.** Dropping a lease does not implicitly
   fulfill its request. A live operation must report failure or
   explicitly cancel.
9. **Make ownership transitions transactional.** Validate before
   consuming a handle; consume and null it on success. Invalid sealing
   or fulfillment leaves the input handle owned by the caller for
   cleanup. Duplicate completion is rejected.

C cannot enforce that a saved pointer is never used after sealing.
This remains an FFI safety contract. The C++ RAII wrapper should make
the correct lifecycle the default, including retaining a lease until
asynchronous I/O has actually stopped, not merely until cancellation
has been requested.

## Implemented phase 2: immutable write leases

[`describe`](../../contentauth-c2pa-cpp/cpp/src/sign.cpp) acquires a
`WriteBuffer` rather than copying a Rust write payload into a C++ vector:

```text
Rust-owned immutable buffer
    -> C++ pointer/length lease
    -> pwrite()
    -> acknowledge Written and release lease independently
```

The file builder and session bridge already use immutable `bytes::Bytes`;
phase 2 reuses that representation rather than introducing `Arc<Vec<u8>>`.
A source-copy read moves its allocation into a write request. Forwarding,
the ABI's outstanding-write map, and each lease clone only shared ownership,
not payload bytes.

The C ABI exposes `c2pa_sm_build_write_acquire` and
`c2pa_sm_write_buffer_free`. Any outstanding write may have multiple
immutable leases, including after a later `advance` clears the fresh-request
batch. Accepted `Written` or failure replies remove the session's retained
entry; incorrect replies leave it available. Existing leases remain valid
after acknowledgment, failure, or session destruction.

In C++, `WriteRequest::bytes` owns a move-only `WriteBuffer`.
`bytes.view()` returns `ConstBytes { const uint8_t *data, size_t size }`.
`SyncBuildHost::write(stream, offset, view)` uses that pointer directly:
the POSIX host calls `pwrite`, the stream host writes from it, and the
memory host copies it into its output storage as its actual I/O operation.

An asynchronous host must retain the owning request or buffer, not just
the view, until actual I/O has stopped. Cancellation alone is not I/O
completion. Releasing a lease does not acknowledge a write; acknowledging
a write does not release the host's lease. Immutable bytes may be read
concurrently, but session calls and ownership transfers remain serialized.

## Verification and acceptance criteria

Phase 1 validation on macOS includes 37 Rust ABI tests, all 108 CTest
tests/examples in plain, AddressSanitizer, and ThreadSanitizer builds,
and warning-free Clippy. Rust ABI line coverage is 98.42% overall
(98.14% for the signing module). The C++ sanitizer builds instrument
C++ code, not the Rust static library.
An LLVM-instrumented run of all 103 GoogleTests covers 99.71% of
`sign.cpp` lines and 99.11% of `sign_async.cpp` lines, with every
function in both implementation files executed. Linux-only POSIX fault
injection tests are not exercised by these macOS runs.

Tests check lease-to-reply allocation identity, reverse-order hash reads
for a 512 KiB asset, invalid ownership transitions, and completed reads
after session destruction. Blocking, pooled, and coroutine signing still
read back as `Trusted`.

Phase 2 validation on macOS passes 126 Rust tests across the ABI, session
bridge, and file-builder suites, plus all 110 CTest tests/examples in
plain, ASan, and TSan builds. ABI line coverage is 98.54% overall
(98.35% for the signing module); all newly added write-lease ABI lines
are exercised. The 105-test C++ coverage run covers 99.73% of `sign.cpp`
lines and 99.11% of `sign_async.cpp` lines, with every function in both
files executed. Formatting, Clippy, rustdoc, and generated-header
verification pass. Linux-only fault injection remains unrun on macOS.

* **Allocation identity:** the pointer filled by C++ is the allocation
  consumed by Rust before hashing; merely measuring throughput is not
  proof of copy elimination.
* Multiple concurrent reads can complete in reverse order and produce
  the same hash.
* Advancing the session does not invalidate other checked-out buffers.
* Session destruction with I/O outstanding, followed by late
  completion, does not cause use-after-free or leaks.
* Short reads, host failures, duplicate acquisition and completion,
  wrong-session fulfillment, alternate reply paths, and abandoned
  leases exercise explicit failure and cleanup paths.
* Failure to seal or fulfill preserves caller ownership of the handle.
* Blocking, pooled, and coroutine drivers preserve the same ownership
  guarantees.
* Signed output still reads back as `Trusted`.
* ASan and TSan cover lifetime and completion races in the C++ binding;
  Rust tests exercise handle validation and allocation transfer.
* A large source-copy operation retains
  its payload allocation through Rust forwarding and the C++ write.

## Delivered scope and stopping point

Phase 1 implements independent read leases and `read_into` across the
blocking, pooled, and coroutine drivers. This removes the file-read-to-
hasher copy while preserving the engine's existing owned byte replies
and the host's control over all I/O and networking.

Phase 2 adds immutable write leases to the same drivers. Tests verify a
multi-megabyte source's read allocations survive forwarding into writes,
multiple leases share a pointer, acknowledgment does not revoke storage,
and delayed C++ writes remain safe after driver cancellation.

Signing input, signature replies, timestamps, certificate/settings data,
and report serialization remain outside these phases. Operating-system
I/O and memory-host read/write copies also remain; this is not a claim
that the entire signing pipeline is copy-free.
