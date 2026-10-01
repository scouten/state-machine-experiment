# c2pa-node-compat-addon

c2pa-node's `Reader` API on this workspace's sans-I/O engine, with a
different split of labor from c2pa-node's own: **Node owns every
asynchronous operation; Rust holds a state machine and is only ever called
synchronously.**

| | c2pa-node (`neon_reader.rs`) | this addon |
|---|---|---|
| Who reads the file | a tokio worker thread, via a sync `Read + Seek` | Node: `FileHandle.read()` (libuv's pool), or any async source |
| Who fetches OCSP | `reqwest` inside c2pa-rs | Node's `fetch` — proxies, agents, mocks are Node's business |
| Threads in Rust | a process-wide multi-thread tokio runtime | none |
| Shared state | `Arc<tokio::sync::Mutex<Reader>>` | none: a `Reader` is a parsed JSON snapshot |
| Sync accessors | `rt.block_on(mutex.lock())` on the JS thread | plain JS over the already-parsed JSON |
| Promise plumbing | `Deferred` + `Channel` settled from a worker | ordinary `async` JS; the addon has no `futures` feature |
| Concurrency / back-pressure | the runtime's | the caller's (`concurrency` option) |
| Clock | the system's | the caller's (`now` option): reproducible reads |
| Rust exports | promise-returning functions | 4 synchronous functions (`src/lib.rs`, ~150 lines) |

## The conversation

```js
const session = native.sessionNew("image/jpeg", settingsJson);
for (;;) {
  const step = native.sessionAdvance(session);   // sync, one bounded slice of work
  if (step.done) break;
  for (const request of step.requests) {          // reads, length, clock, OCSP
    answer(request).then(r => native.sessionFulfill(session, request.id, ...r));
  }
  await Promise.race(inFlight);                   // Node decides when to come back
}
const json = native.sessionFinish(session);       // string, or null: no manifest store
```

That loop is `index.mjs`'s `readStore`, about forty lines. The engine
pipelines its hard-binding hash as a window of 64 KiB chunk reads, so
`advance` hands up several reads at once and Node overlaps them; replies
may come back in any order.

## Try it

```sh
npm run build   # cargo build --release, then copies the cdylib to index.node
npm test        # 13 tests under node:test
./coverage.sh   # coverage for the JS driver and the Rust addon (needs cargo-llvm-cov)
npm run demo    # event-loop delay while hashing a large file
```

Tests cover: path / buffer / custom async source giving identical JSON;
format sniffing; `null` for no manifest store; c2pa-rs `Debug` strings as
error names (`C2pa(UnsupportedType)`); the host choosing 1, 2, or N reads
in flight; timers firing throughout a slow read; eight reads interleaving
on one thread in well under the serial time; and a failing source
rejecting the read.

`coverage.sh` produces both halves of the Node side from one instrumented
run: `lcov.info` for the JavaScript driver (Node's built-in coverage) and
`lcov.rust.info` for the Rust addon (cargo-llvm-cov, exercised by loading
the cdylib into Node). Currently about 98% of the driver's lines and 87%
of the addon's; the uncovered remainder is the OCSP-request marshalling
(no fixture makes the engine issue one) and a file shrinking mid-read.
CI's `node-addon` job runs it and uploads both reports to Codecov under
the `node-addon` flag. The Rust core (`contentauth-c2pa-node-compat`)
is covered by the workspace's own coverage job.

Measured here (release build, 256 MB file whose every byte is hashed,
`monitorEventLoopDelay` at 1 ms resolution):

```
concurrency 1: 0.50 s, 510 MB/s, event-loop delay p50 1.0 ms, p99 1.2 ms, max 4.6 ms
concurrency 8: 0.33 s, 773 MB/s, event-loop delay p50 1.0 ms, p99 1.6 ms, max 5.1 ms
```

The JS thread is busy only for the length of one `advance` — hashing a few
64 KiB chunks — so the loop stays responsive even though the hashing
itself happens on it.

## Honest trade-offs

* **Hashing runs on the JS thread**, in small slices. The numbers above
  show that is cheap for SHA-256 at this chunk size, but a host that
  wants it off-thread has a clean option the engine already supports:
  construct and drive the `NodeSession` inside a `worker_threads` Worker.
  Same Rust, same loop, different thread; nothing in the crate changes.
* **Every request crosses the N-API boundary** (a `Buffer` copy per
  chunk). c2pa-node reads inside Rust and crosses once per call. The
  throughput above says this is not the bottleneck, but it is the cost.
* **Not covered**: `fromManifestDataAndAsset`, `resourceToAsset`,
  `Builder`, signers, Trustmark, formats other than JPEG. A `Builder`
  would take the same shape — `BuilderSession`'s `Sign`/`Timestamp`
  requests are the ones c2pa-node's `CallbackSigner` already answers by
  calling back into JavaScript, here simply the normal path rather than a
  special one.

This directory is its own Cargo workspace: a Neon `cdylib` leaves N-API
symbols to the Node process, so it cannot link under the root workspace's
`--all-features` test jobs. CI builds and tests it in a separate job.
