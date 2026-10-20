# PR 47: Rust payload sharing is not end-to-end JS zero-copy

## Answer

**No: [PR 47](https://github.com/scouten/state-machine-experiment/pull/47)
does not make the JS binding work unnecessary.** It supplies the right Rust
ownership primitive and removes important **within-Rust** copies. The
Neon/Wasm marshaling and main-thread/Worker protocol remain separate ownership
boundaries. They still copy in the current prototype.

We should rely on Rust for immutable shared payload ownership, cheap cloning
and slicing, and synchronous request servicing. We should not reproduce those
internals in JS. Binding glue must preserve that ownership advantage instead
of immediately materializing another Vec, and JS must separately manage its
Buffer views, structured clones/transfers and caller-mutation contract.

This is a **scoped source/ownership analysis**, not a full correctness/security
review or a merge recommendation. No PR code was merged or applied, no PR
tests/benchmarks were run here, and no copy optimization was implemented.

## Evidence baseline

- PR title: "feat: Share bulk byte payloads and avoid cloning synchronous host requests".
- Inspected head: **`701006682727fef2ac834004ee8b7c812dda4e64`**.
- Base: `b186661b86f1ed348aa964c7e8c34059753f3267`.
- Branch: `explore/zero-copy-payloads`; open at inspection.
- Comparison: current shared Worker prototype, whose bridge is
  [`contentauth-c2pa-session-bridge`](../../contentauth-c2pa-session-bridge/),
  with separate [Neon signing addon](../../c2pa-node-sign-addon/src/lib.rs)
  and [Wasm binding](../../contentauth-c2pa-wasm/src/build.rs).

The PR is based on the older topology: it updates the Node-named session
wrappers. Its head tree does **not** contain our `js` package,
`contentauth-c2pa-session-bridge` or standalone `contentauth-c2pa-wasm`.
An eventual integration must reconcile those wrapper edits into the
runtime-neutral bridge and standalone Wasm glue; "bindings updated" in the PR
description does not mean this newer JS architecture is already optimized.

All PR links below are pinned to the inspected SHA, not the moving branch.

## What Rust supplies

### Shared immutable payloads

The PR
[re-exports `bytes::Bytes`](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-c2pa-primitives/src/lib.rs#L65)
and replaces owned Vec payloads for asset chunks, stores, placeholders,
committed manifests and file-builder writes.

- A `Bytes` clone shares storage rather than cloning all payload bytes.
- Slices can share an allocation; the PR's
  [in-memory host](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-c2pa-format/src/test_util.rs#L88)
  returns slices instead of fresh Vec copies.
- Moving a Vec into Bytes can adopt its allocation. That is valuable **after**
  a host already owns a Vec; it does not make the preceding JS-to-Rust copy
  disappear.
- The final manifest can be shared between commit request and build report.
  Hashing holds shared chunks and borrows their contents.
- It does not mean all Rust copies disappear: mutable placeholder construction
  deliberately retains a copy. File-builder source copying is still bounded
  at 1 MiB per chunk, not removed.

This is ordinary immutable ownership sharing, not shared mutable access to a
V8 Buffer or arbitrary Wasm linear-memory view.

### Borrowed synchronous request handling

[`Session::respond`](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-state-machine/src/session.rs#L111)
borrows one outstanding request, gets an owned reply, then fulfills it before
moving to the next. This removes request cloning/intermediate reply batches
in synchronous Rust hosts.

Our JS host awaits file reads, signing and Worker messages. A Rust request
borrow cannot simply be held across that JS asynchronous boundary. The
existing `advance/outstanding/fulfill` contract remains the correct async-host
surface; there is no need to move async into Rust or replace the JS loop with
`respond`.

### Allocation evidence: useful, but different metric

The PR reports total allocations on a 16 MiB JPEG:

| Rust-only measurement | Before | After |
| --- | ---: | ---: |
| Build allocated bytes | 50.9 MB | 34.0 MB |
| In-memory read allocated bytes | 17.0 MB | 0.11 MB |

These are the PR author's measurements, not independently reproduced here.
They are **not peak RSS**, JS/native boundary measurements, browser memory,
or the 64 MiB file-output comparison from our experiments. In particular, a
Rust in-memory host can slice an existing Rust allocation; a JS Buffer host
does not automatically acquire that property.

## Copies that remain

### Even the PR's flattened bridge still owns Vec payloads

In the PR's old signing wrapper:

- [`PendingRequest::Write.bytes`](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-c2pa-node-compat-sign/src/session.rs#L92)
  remains `Vec<u8>`.
- [`describe`](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-c2pa-node-compat-sign/src/session.rs#L356)
  uses `bytes.clone().into()` to convert core Bytes back to Vec. A Bytes clone
  is cheap, but that final conversion is **not generally zero-copy**:
  the session still owns the original payload, so unique allocation ownership
  cannot be assumed.
- [`finish`](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-c2pa-node-compat-sign/src/session.rs#L290)
  converts the shared manifest back into Vec too.
- [`engine_reply`](https://github.com/scouten/state-machine-experiment/blob/701006682727fef2ac834004ee8b7c812dda4e64/contentauth-c2pa-node-compat-sign/src/session.rs#L398)
  can move an already-owned Vec reply into Bytes, avoiding a further internal
  copy, but not undoing the JS import copy that created that Vec.

Our neutral [build bridge](../../contentauth-c2pa-session-bridge/src/build/mod.rs)
currently also uses Vec at its flattened public boundary. To carry the PR's
benefit farther, its payload representation must be reconciled deliberately;
mechanically adding `.into()` everywhere can preserve compilation while
discarding part of the memory benefit.

### Node / Neon

Current [signing addon](../../c2pa-node-sign-addon/src/lib.rs):

- Outgoing write payloads and final manifests use `JsBuffer::from_slice`:
  Rust-to-JS copies.
- Incoming byte replies use `JsBuffer.as_slice(...).to_vec()`:
  JS-to-owned-Rust copy.

The [reader addon](../../c2pa-node-compat-addon/src/lib.rs) likewise copies
incoming byte replies into an owned Vec.

Current [Node adapter](../src/node/adapter.mjs):

- Reader replies wrap typed-array backing storage with
  `Buffer.from(value.buffer, value.byteOffset, value.byteLength)` — a view.
- Build replies use `Buffer.from(value)` — another JS copy **before** the
  Neon's `.to_vec()` import copy. This is a concrete, likely removable duplicate
  at binding level, independent of the core PR.

A Rust-to-JS external Buffer could potentially retain a Rust-owned allocation
with a finalizer, avoiding an export copy. That is a separate addon
ownership/lifetime design, not a property of Bytes alone. A mutable JS Buffer
must not alias an allegedly immutable shared Bytes allocation without a
sound ownership/mutation contract. Borrowing JS input for use after the Neon
call returns is not made safe by ref-counting a different Rust allocation.

### Browser / Wasm

Current [Wasm build glue](../../contentauth-c2pa-wasm/src/build.rs) keeps binary
payloads in `Vec<Option<Vec<u8>>>` and clones outgoing write bytes into that
table. Returning a Vec through wasm-bindgen still exports bytes from Wasm
linear memory into JS-owned storage.

Incoming bytes are accepted as borrowed `&[u8]` and then `.to_vec()` creates
session-owned storage. The [reader glue](../../contentauth-c2pa-wasm/src/lib.rs)
has the same input-ownership step. The JS-to-linear-memory marshaling is a
separate copy from that explicit Rust ownership copy.

An owned input Vec moved into Bytes could remove the latter extra copy without
changing core algorithms. It would not remove the JS-to-Wasm copy. Exposing a
Wasm memory view is a different, hazardous contract: memory growth, payload
release, subsequent `advance/fulfill` and awaited JS operations all affect
view validity. No borrowed view should survive arbitrary asynchronous work
without an explicit, tested lifetime rule.

### Main thread / Worker

The [shared client](../src/shared/client.mjs) snapshots caller byte input
and posts messages without transfer lists; Worker result messages also use
structured cloning. Bytes cannot share arbitrary V8 backing stores between
these realms, nor make Wasm memory a transferable caller Buffer.

There are two distinct optimization choices:

1. Transfer an **already-owned internal snapshot/result buffer** instead of
   cloning it again. This can preserve the public non-detaching snapshot
   contract if that allocation is dedicated and no live aliases still need it.
2. Transfer the **caller's original** buffer to avoid the initial snapshot.
   That changes ownership/detaches input and requires an explicit opt-in
   contract. Node pooled Buffers and shared backing stores need special care;
   transferring their whole backing ArrayBuffer is not a safe generic default.

SharedArrayBuffer would require another protocol/mutation/isolation design;
it is not supplied by this Rust PR.

The Node `{ path }` input and file-output sink already avoid whole-asset Worker
transfers and final asset return. Those wins are independent of Bytes and
should be preserved.

## Responsibility and safe next work

| Layer | Rely on PR / Rust for | Remaining binding responsibility |
| --- | --- | --- |
| Engine/domain/formats | Shared immutable chunks/stores/manifests; cheap clone/slice; borrowed synchronous dispatch | Do not duplicate hashing/container logic in JS |
| Neutral session bridge | Owned core payload lifetime | Port/reconcile Bytes into newer bridge; avoid converting shared bulk data back to Vec unnecessarily |
| Node adapter | Owned Rust import remains available | Replace proven redundant JS copies with backing-store views where safe |
| Neon | Rust ref-counted allocation lifetime | Explicit export ownership/finalizer and immutable/mutable alias policy; retain necessary input copy |
| Wasm | Session-owned Bytes after import | Remove duplicate import ownership copy where possible; linear-memory export/import and view lifetimes remain separate |
| Worker protocol | No automatic help from Bytes | Transfer owned internal buffers safely; preserve caller snapshots and cancellation/error behavior |
| File/Blob hosts | Bounded requests remain the contract | Keep requested slices/file reads and direct file output; no whole-asset conversions |

Recommended bounded follow-up, **not implemented here**:

1. Establish the same source hashes, request counts and output validation before
   and after the PR is reconciled into this branch.
2. Separately remove the Node build adapter's extra `Buffer.from(value)` copy,
   preserving immediate native-copy ownership. Test offsets/subarrays,
   caller mutation, signer failures, disposal and recovery.
3. Measure safe transfers of dedicated internal snapshots/results separately;
   assert caller buffers remain attached and unchanged.
4. Compare raw Worker and facade, Buffer/path inputs and Buffer/file outputs;
   instrument copy counts/bytes as well as latency and external peak RSS.
5. Only then consider external Neon Buffers or Wasm memory views if measured
   residual copies justify the more complex lifetime contract.

Do not infer the PR's end-to-end JS benefit from its Rust allocation totals.
Measure the integrated stack. The immediate opportunity is **binding glue and
transport ownership**, not new Rust validation/container features or a claim
that everything should become "zero-copy."
