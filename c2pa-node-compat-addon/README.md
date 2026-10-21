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
| Shared state | `Arc<tokio::sync::Mutex<Reader>>` | none: parsed JSON plus a private immutable native reader retaining embedded bytes |
| Sync accessors | `rt.block_on(mutex.lock())` on the JS thread | plain JS over the already-parsed JSON |
| Promise plumbing | `Deferred` + `Channel` settled from a worker | ordinary `async` JS; the addon has no `futures` feature |
| Concurrency / back-pressure | the runtime's | the caller's (`concurrency` option) |
| Clock | the system's | the caller's (`now` option): reproducible reads |
| Rust exports | promise-returning functions | 4 synchronous session functions plus one retained-resource lookup |

## The conversation

```js
const session = native.sessionNew("image/jpeg", settingsJson, detachedBytes); // optional Buffer
for (;;) {
  const step = native.sessionAdvance(session);   // sync, one bounded slice of work
  if (step.done) break;
  for (const request of step.requests) {          // reads, length, clock, OCSP
    answer(request).then(r => native.sessionFulfill(session, request.id, ...r));
  }
  await Promise.race(inFlight);                   // Node decides when to come back
}
const result = native.sessionFinish(session);     // { json, reader }, or null: no store
```

That loop is `index.mjs`'s `readStore`, about forty lines. The engine
pipelines its hard-binding hash as a window of 64 KiB chunk reads, so
`advance` hands up several reads at once and Node overlaps them; replies
may come back in any order.

## Try it

```sh
npm run build   # cargo build --release, then copies the cdylib to index.node
npm test        # 39 tests under node:test
./coverage.sh   # coverage for the JS driver and the Rust addon (needs cargo-llvm-cov)
npm run demo    # event-loop delay while hashing a large file
```

### Five-platform baseline CI

[Node platform baseline](../.github/workflows/node-platforms.yml) runs on PRs
and pushes to `main`, using native hosts rather than cross-compilation alone:

| Rust target | Native runner |
|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `aarch64-apple-darwin` | `macos-15` |
| `x86_64-pc-windows-msvc` | `windows-2022` |

Each job uses Rust 1.96.0, builds both addons, asserts Node's OS/architecture,
and runs the same binaries under Node 22 and 24. The selected suites are
`test/build.test.mjs`, `test/reader.test.mjs`, and the signing addon's
`test/sign.test.mjs`: file/buffer/async reads, ES256 sign/read-back as Trusted,
concurrency, failure cleanup, output replacement, and timestamp handling.
This is a platform baseline, not full SDK feature parity; it deliberately does
not substitute for either addon's complete `npm test` suite. Coverage remains
in the existing Linux jobs.

Successful jobs retain both tested `index.node` files, in their respective
addon directories, as `node-baseline-<target>` artifacts for 14 days. These are
CI artifacts, not installable npm releases or a minimum-OS support promise.

To reproduce a target build on its native host, set `CARGO_BUILD_TARGET` to
the matching triple before `npm run build`. Both build scripts honor that
variable and `CARGO_TARGET_DIR`; without a target, host builds work as before.
From the repository root, after building both addons, run the exact baseline:

```sh
node --test c2pa-node-compat-addon/test/build.test.mjs c2pa-node-compat-addon/test/reader.test.mjs c2pa-node-sign-addon/test/sign.test.mjs
```

Tests cover: path / buffer / custom async source giving identical JSON;
format sniffing; `null` for no manifest store; c2pa-rs `Debug` strings as
error names (`C2pa(UnsupportedType)`); the host choosing 1, 2, or N reads
in flight; timers firing throughout a slow read; eight reads interleaving
on one thread in well under the serial time; and a failing source
rejecting the read.

## Detached manifest reads

`Reader.fromManifestDataAndAsset(manifestData, asset, settings, options)` accepts
a `Buffer` containing a detached manifest store, with the same path/buffer/custom
async sources, settings and host options as `fromAsset`. It snapshots that buffer
before any await and supplies it to the existing sans-I/O file session. Source
bytes still undergo hard-binding validation. Explicit malformed/empty sidecars
reject rather than falling back to an embedded store or fetching a remote one;
unrelated valid stores report their own label and binding failures.
`isEmbedded()` is false for explicit bytes even if the asset also carries a store;
`remoteUrl()` is empty. Ordinary embedded reads keep their existing behavior.

Six actual-Node tests adapt upstream detached buffer/file cases using a real
c2pa-rs-signed, store-free JPEG with two ingredient data resources and a thumbnail.
The complete Trusted report equals its unfiltered c2pa-rs golden under equivalent
named trust settings. Tests also cover asset tampering, explicit-store precedence,
malformed/invalid arguments, source errors, snapshot isolation, concurrent trust
settings, recovery and retained resources after source closure. Native tests compare
against the async browser host; the signing addon tests the constructor against
freshly signed output. These adapted cases do not increase unchanged upstream
ledger coverage. Full Context/settings/size-limit API parity remains separate.

## Embedded resources

`await reader.resourceToAsset(uri, { buffer: null })` returns
`{ buffer: Buffer, bytes_written: number }`, matching c2pa-node's result shape.
A supplied destination buffer is not modified or used as a prefix.
`await reader.resourceToAsset(uri, { path })` writes/truncates that caller-chosen
file asynchronously and returns `{ buffer: Buffer.alloc(0), bytes_written }`.
File errors reject; destination paths are the caller's responsibility.

The native reader is retained behind a private field until garbage collection.
It shares the browser adapter's exact absolute self JUMBF URI lookup for claim
thumbnails, generator icons, ingredient thumbnails and data. Every result is an
independent copy; no source read, network request, lock or async Rust work is
needed. This retains resource payloads, not the whole asset. Copying a resource
still runs synchronously on the JS thread and is not a large-resource streaming
API. Resource extraction does not establish trust or alter validation results.

Six actual-Node cases adapt the pinned upstream file-output test to the local
claim-thumbnail fixture and verify the legacy buffer/file shapes, source-file
removal, truncation, exact generated-fixture bytes, positional references and
copy isolation, no post-read source/network access, tamper failures, strict
URI/destination errors and recovery. Unsupported databox reports still reject.
These are migration cases, not additional unchanged upstream ledger passes.

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

## OCSP is a request the asset makes of the host

An OCSP responder URL comes from the *asset's* certificate, so it is
untrusted input, and with `verify.ocsp_fetch` on (it is off by default)
the driver would POST to wherever it points. The driver therefore asks
`ocspPolicy(url)` first (default `defaultOcspPolicy`: `http(s)` only, no
embedded credentials, no literal loopback / private / link-local /
`localhost` address, including numeric and IPv4-mapped spellings), never
follows redirects, and bounds the response at 1 MiB (declared length checked first, then the body read incrementally and abandoned at the limit, so memory is bounded, not just the result). A policy cannot see
through DNS, so a server reading untrusted assets with OCSP on should also
pass a `fetch` whose resolver rejects private addresses. That seam exists
because the host, not the Rust engine, owns the network.

## Honest trade-offs

* **Hashing runs on the JS thread**, in small slices. The numbers above
  show that is cheap for SHA-256 at this chunk size, but a host that
  wants it off-thread has a clean option the engine already supports:
  construct and drive the `NodeSession` inside a `worker_threads` Worker.
  Same Rust, same loop, different thread; nothing in the crate changes.
* **Every request crosses the N-API boundary** (a `Buffer` copy per
  chunk). c2pa-node reads inside Rust and crosses once per call. The
  throughput above says this is not the bottleneck, but it is the cost.
* **Not covered**: databox/external resources,
  full `Builder`, signers, Trustmark, formats other than JPEG/TIFF. A `Builder`
  would take the same shape — `BuilderSession`'s `Sign`/`Timestamp`
  requests are the ones c2pa-node's `CallbackSigner` already answers by
  calling back into JavaScript, here simply the normal path rather than a
  special one.

This directory is its own Cargo workspace: a Neon `cdylib` leaves N-API
symbols to the Node process, so it cannot link under the root workspace's
`--all-features` test jobs. CI builds and tests it in a separate job.
