# Shared JavaScript host over Wasm and Neon

## Scope and status

Use one JavaScript facade, Worker protocol and session-driving loop in both
environments. Run that loop in a browser module Worker over Wasm, or a Node
`worker_threads.Worker` over Neon. Rust remains synchronous and sans-I/O.
Neither Tokio nor a custom scheduler is required for this example.

This is a **read and baseline-signing architecture proof**, not a replacement
SDK or a legacy API migration. Reading exercises validation, settings and
reporting; signing exercises source/output I/O requests and an asynchronous
caller-owned signer across the Worker boundary. Both use existing Rust domain
functionality, with shared JavaScript transport, isolation and lifecycle logic.
Signing is limited to the existing JPEG/ES256 baseline, without timestamps.

This package originated as a proof on branch `ale/shared-worker-poc`, based on
`main` at `97fac9b`. Its implementation, fixtures, generated artifacts and
findings now live in this package; the standalone Wasm binding is in the
repository-level `contentauth-c2pa-wasm` crate. No migration-branch changes or
domain features were copied.

## Architecture

```mermaid
flowchart TB
    App["Application: await client.read / sign"]
    Client["Shared JS Client<br/>snapshot, IDs, errors, disposal"]
    Service["Shared Worker service<br/>serialized operations"]
    Drive["Shared JS host loop<br/>advance / answer / fulfill / finish"]
    Source["Worker-owned source<br/>bytes / Blob slices / Node file reads"]
    Browser["Browser adapter<br/>synchronous wasm-bindgen calls"]
    Node["Node adapter<br/>synchronous Neon calls"]
    Session["Portable read / build bridges<br/>plain-data requests and replies"]
    Reader["FileReadSession / FileBuilderSession<br/>C2PA reader / builder"]
    Signer["Application-owned async signer<br/>key stays outside Worker and Rust"]
    App --> Client
    Client -->|"postMessage: bytes / Blob / Node path"| Service
    Service --> Drive
    Drive --> Source
    Service -->|"sign request: operation + request ID"| Client
    Client --> Signer
    Signer -->|"signature or error"| Client
    Client -->|"signer reply bypasses operation queue"| Service
    Drive --> Browser & Node
    Browser --> Session
    Node --> Session
    Session --> Reader
```

The application and service are in different execution realms. Platform files
start Workers, normalize message/error/termination APIs, translate
binding values and open platform-specific sources. The **same imported modules**, not parallel implementations,
own these behaviors:

| Module | Shared responsibility |
| --- | --- |
| [client.mjs](src/shared/client.mjs) | Public Promise API; request identity; input snapshot; signer callbacks; reply/error handling; disposal |
| [service.mjs](src/shared/service.mjs) | Worker command dispatch; serial operation queue; independently dispatched signer replies |
| [drive.mjs](src/shared/drive.mjs) | Read/build session progression; source/output bytes; host replies; request accounting; cleanup |
| [Node source](src/node/source.mjs) | Worker-owned file handle, positioned range reads and close; no Rust changes |
| [contract.mjs](test/contract.mjs), [signing.mjs](test/signing.mjs) | Identical read and signing acceptance checks in Node and all three browsers |

The runtime-neutral
[`contentauth-c2pa-session-bridge`](../contentauth-c2pa-session-bridge/)
crate owns `ReadSessionBridge` and `BuildSessionBridge` with their plain-data
request/reply types and shared compatibility context/report types. The
standalone [Wasm binding](../contentauth-c2pa-wasm/src/lib.rs) consumes the
read bridge, and its [signing boundary](../contentauth-c2pa-wasm/src/build.rs)
consumes the build bridge. Both remain synchronous; neither duplicates C2PA
logic or adds a Rust async runtime.

Wasm serializes request metadata as JSON but passes bulk build write payloads
as binary byte arrays through wasm-bindgen. Each payload is consumed once
before the next advance; byte storage remains owned/copied, not an unsafe view
into Wasm memory. Neon returns objects and expects Buffers for byte replies.
Adapters normalize those differences without changing the shared host.
Small signing-input and final manifest arrays still use JSON in the Wasm
adapter. The original all-JSON path remains only as an experiment control.

### Neutral session bridge

The bridge crate now owns the read and build workflows plus their
`PendingRequest`, `Reply` and `Step` vocabularies, the signing `Stream` and
`SignReport`, and compatibility context/report/error types. Its
[read bridge](../contentauth-c2pa-session-bridge/src/read/mod.rs) and
[build bridge](../contentauth-c2pa-session-bridge/src/build/mod.rs) adapt the
typed file sessions for language bindings: they map opaque engine request IDs
to numeric handles, surface each new request once, translate replies, and
return the compatibility results. They do not call Node APIs, use Neon, perform
I/O, spawn threads, or schedule work. Byte reads, length, clock, OCSP,
timestamps and signing remain host responsibilities.

The historical Node association was API-shaped: the first wrapper accepted
c2pa-node-style format/settings arguments and mapped a missing manifest to
`None` for the JS `null` result. The same compatibility contract is now owned by
the neutral bridge and consumed by both bindings. Compatibility policy remains
above the generic state-machine engine; the bridge is not a Worker, host driver,
scheduler or new validation engine.

Node-specific code should remain in the Neon binding and Node host/Worker
adapter; browser-specific code should remain in the Wasm binding and browser
host/Worker adapter. The shared JS driver continues to use the same bridge
protocol in both.

### Reuse beyond JavaScript

The bridge is language-neutral, not merely shared between two
JavaScript runtimes. A C++, Python, Swift, Kotlin or C# host could use the same
`advance` / `fulfill` / `finish` protocol, answering requests with its own I/O,
clock and networking APIs and choosing its own concurrency model. Promises,
Workers and JavaScript event loops are not requirements of that protocol.

The existing Rust enums, strings and byte vectors are **not a universal
foreign-function ABI**. Each language still needs a thin adapter for value/error
conversion, session ownership and disposal, and exact representation of 64-bit
offsets and request handles. Neon and wasm-bindgen provide the two adapters
exercised here; another language would need its own binding tooling or a
deliberately designed C ABI.

Protocol reuse must also be distinguished from legacy API compatibility. The
current wrapper carries c2pa-js-oriented settings JSON, report/error shapes and
missing-manifest behavior. Other languages may reuse those conventions, but
should not have to adopt them just to drive the state machine. Keep legacy
compatibility facades separate from the reusable session protocol; existing
Rust hosts can already use the underlying typed sessions directly.

The JavaScript experiments prove the two JS consumers. The subsequently merged
[C++ reader binding](../contentauth-c2pa-cpp/) also drives the neutral read bridge
through its own C ABI and hosts, not this JS package. Python and a universal ABI
remain unimplemented; no further abstraction is required for those possibilities.

The following is the current ownership model. The dotted Python path is a
possible, unproven additional consumer.

```mermaid
flowchart TB
    JS["Shared JS host<br/>browser and Node Workers"]
    Wasm["Browser binding<br/>wasm-bindgen"]
    Neon["Node binding<br/>Neon"]
    CPP["C++ reader hosts + C ABI adapter<br/>contentauth-c2pa-cpp"]
    Python["Possible Python host + extension adapter<br/>not implemented or tested"]
    Bridge["ReadSessionBridge + BuildSessionBridge<br/>contentauth-c2pa-session-bridge<br/>plain-data requests / replies"]
    File["FileReadSession / FileBuilderSession<br/>typed Rust sessions"]
    Rust["Existing Rust host<br/>direct typed access"]
    JS --> Wasm & Neon
    Wasm --> Bridge
    Neon --> Bridge
    CPP -->|"read bridge"| Bridge
    Python -.-> Bridge
    Bridge --> File
    Rust --> File
```

## Ownership and execution

### Node compatibility facade

The opt-in [compatibility namespace](src/node/compat.mjs) offers a narrow
c2pa-node-shaped API over one reused Worker:

```js
import { createNodeCompat } from "./src/node/compat.mjs";
const sdk = createNodeCompat();
const { Reader, Builder, CallbackSigner, Context } = sdk;
try {
  const context = new Context({
    trust: { userAnchors: inlinePem },
    verify: { ocspFetch: false, remoteManifestFetch: false,
      verifyAfterReading: true, verifyTrust: true, verifyAfterSign: false },
  });
  const reader = await Reader.fromAsset({ path: "./signed.jpg" }, context);
  const json = reader?.json();
  const builder = await Builder.withJsonAsync(definition, context);
  const signer = CallbackSigner.newSigner({
    alg: "es256", certs: [pemCertificateBuffer],
    reserveSize: 10000, directCoseHandling: false,
  }, async (data) => signRawEs256(data)); // Buffer in, 64-byte r||s out.
  const output = { buffer: null }; // Or { path: "./output.jpg" }.
  const manifest = await builder.signAsync(signer, { path: "./input.jpg" }, output);
  // manifest and output.buffer are Buffers; a file destination has no buffer.
} finally {
  await sdk.dispose();
}
```

This is a compatibility **slice**, not an alias for the entire SDK.
Supported: Buffer/file assets, JPEG MIME aliases/omitted MIME on reads,
`Reader.json/activeLabel/getActive`, unsigned `null`, `Builder.withJsonAsync`
and raw ES256 `CallbackSigner` signing to Buffer/file destinations.
Each namespace owns one Worker; reports are snapshots, not native handles.
Unlike the original SDK, disposal is explicit and rejects queued operations.

Settings accept the local `Context` or a raw object with inline
`trust.userAnchors` and the offline verification switches shown above.
Unsupported settings/configurations reject; no URL fetching or suppressed
validation is emulated. Only `reserveSize: 10000` is accepted as the experiment
configuration; it does not reconfigure Rust's manifest reservation. Definitions
must already satisfy the existing baseline (including instance ID and label).
This facade does not add RNG, actions checks, formats or other Rust features.

Missing migration surfaces include native handles/resources, detached/remote
manifests, LocalSigner/identity/timestamp signing, mutable builder workflows,
legacy JSON/TOML settings, full error-string equivalence and the existing SDK's
10 GB reader size-limit/error policy. Reader report fields/validation remain
exactly those supplied by the current Rust bridge. Default trust behavior is
not claimed equivalent to the reference SDK.

Run `npm run test:compat` against the built sibling SDK, and
`npm run benchmark:compat` for isolated raw-Worker/facade/reference comparisons.
See the [compatibility experiment](experiments/2026-10-16-node-compat-facade.md).

### Shared client ownership

- One Worker per client. Workers are reused; top-level operations are queued.
  Pending requests within one operation can be answered as a batch.
- Native handles and Wasm objects never cross Worker boundaries. Results are
  plain reports and, for signing, output/manifest bytes and exclusion ranges.
- `read()` and `sign()` accept `Uint8Array`, `Blob` and `File`; the Node client
  also accepts `{ path: "/path/to/asset.jpg" }`, matching c2pa-node's input shape.
  Byte arrays are copied before the first await, then structured-cloned;
  caller buffers remain attached and mutation cannot change a queued operation.
  Immutable Blobs/Files are sent through structured cloning,
  without a whole-input `arrayBuffer()` conversion. The Worker fulfills each
  source request with `slice(start, end).arrayBuffer()`.
  File names and MIME hints do not select a handler or set the output title:
  callers name the format (`{format}` on `read` and `sign`; JPEG by default, TIFF/DNG also supported), and signing metadata comes from the definition.
  Node 24.18 rejects direct `fs.openAsBlob()` inputs as non-cloneable; derived
  file-backed wrappers may expose a Node runtime bug. See the
  [experiment report](experiments/2026-10-16-file-blob-memory.md).
- Node paths are resolved to absolute strings before the first await; the
  descriptor is snapshotted, **not the file contents**. The Worker opens a
  regular file when its queued operation starts, uses positional exact reads,
  and closes it before replying on success or failure. It opens without blocking
  and checks the opened handle, so named pipes reject without stalling the queue.
  Keep the file unchanged
  until the operation finishes. Truncation/short reads fail explicitly; this
  does not detect every concurrent same-length rewrite or promise a filesystem
  snapshot. Reader requests are at most 64 KiB for the tested assets; builder
  source-copy requests are bounded at 1 MiB by the existing Rust session.
  Prefer paths for Node disk assets, not `fs.openAsBlob()`.
- Signing also snapshots the definition and public certificates. The signer
  function and private key stay in the application realm. Only the COSE signing
  input and raw signature/error cross the Worker protocol.
- By default, build output is buffered in a growable in-memory array inside
  the Worker, then copied and cloned back. Node can instead supply a destination
  path: the Worker writes/reads a temporary file in bounded requests and renames
  it into place after successful signing, returning metadata rather than asset
  bytes. See [file-output signing](#node-file-output-signing).
- Blob/File inputs avoid eager whole-source byte materialization in this host.
  They do not promise constant total memory, zero-copy transfer, streamed output
  or a measured peak-memory improvement. Wasm still copies requested bytes.
- Successful `finish` consumes the Rust session. Wasm wrappers are explicitly
  freed in `finally`; Neon error handles become eligible for isolate GC.
  Client disposal terminates its Worker, releasing that isolate's resources.
- Disposal rejects pending calls. It is **abrupt termination**, not graceful
  cancellation. Node disposal waits for Worker termination and removes tracked
  temporary output files; failed operations retain their temporary paths so
  disposal can retry a failed unlink. Cleanup errors are surfaced, not ignored.
  An output already renamed into place stays committed.
  There are no Worker-owned network operations. Caller-owned signing cannot be cancelled by terminating the
  Worker; its late success/rejection is consumed without posting a reply.
- No periodic task yields are inserted. A busy Worker can delay its own control
  messages; the application remains on a separate event loop. Responsive
  cancellation/progress or concurrent shared-Worker execution is not promised.
- OCSP, timestamps and unrecognized host requests fail explicitly. Core
  validation and manifest generation remain Rust-owned.

### Signer callbacks and queueing

The same client methods accept any supported source representation:

```js
const readResult = await client.read(fileInput.files[0], { settings });
const signed = await client.sign(new Blob([jpegBytes], { type: "image/jpeg" }),
  definition, signer);
// signed.asset and signed.manifest remain Uint8Array values.
```

With the Node client, use the file directly without a caller-side `readFile`:

```js
const report = await client.read({ path: "./input.jpg" }, { settings });
const signed = await client.sign({ path: "./input.jpg" }, definition, signer);
```

This adds input-shape parity, not a drop-in legacy `Reader`/`Builder` shim.
Signing defaults to buffered bytes; a Node destination path is optional.
The [Node file-path memory proof](experiments/2026-10-16-node-file-path-memory.md)
compares both input representations against the current Node SDK in isolated
processes:

```sh
npm run benchmark:path
```

It uses the existing generated fixtures and SDK benchmark metadata (prepare
with `npm run fixtures` and `node benchmarks/sdk-node.mjs` after building the
bindings/reference SDK). Results go to ignored `results/path-node.json`.

### Node file-output signing

Pass a fourth argument to write the signed asset to disk:

```js
const result = await client.sign({ path: "./input.jpg" }, definition, signer,
  { path: "./signed.jpg" });
// result.path: absolute destination; result.outputBytes: file length.
// result.manifest, result.exclusions and result.stats remain available.
// result.asset is absent: the signed asset is not loaded/cloned back.
```

Bytes input also works with a file destination. The destination path is
snapshotted/resolved before awaiting Worker startup. Only Node accepts it;
browser clients reject file destinations explicitly.

The Worker exclusively creates an unpredictable temporary file beside the
destination, answers output reads/writes with positioned filesystem I/O, then
closes and renames the completed file. An existing destination is replaced only
on success, not truncated in advance; a destination symlink is replaced rather
than followed. Failed sessions, signer calls and renames remove the temporary
file. Await `client.dispose()` for cleanup after cancellation.

The destination directory must already exist. This is atomic replacement on
the tested macOS filesystem, **not crash-durable storage**: no `fsync` guarantee,
and killing the entire process can leave temporary files. Cancellation racing
with the final rename can reject a call whose output already committed.
Permissions/metadata of an existing destination are not preserved; new files
use mode `0600` subject to the process umask.

The [file-output experiment](experiments/2026-10-16-node-file-output-memory.md)
compares buffered and file destinations in both SDKs:

```sh
npm run benchmark:output
```

No source conversion is required at the call site. A File's name/type are not
copied into the manifest; set the title explicitly in `definition`.

```mermaid
sequenceDiagram
    participant A as Application / shared client
    participant W as Worker / shared service
    participant R as Rust builder via Wasm or Neon
    A->>W: build(operation ID, source, definition, certificates)
    W->>R: advance / fulfill byte requests
    R-->>W: Sign(request ID, algorithm, COSE bytes)
    W->>A: signer request(operation ID, request ID)
    Note over W: Build awaits reply; message handler stays available
    A->>A: await caller-owned signer
    A->>W: signature or error(operation ID, request ID)
    Note over W: Dispatch reply outside top-level operation queue
    W->>R: fulfill signature, advance, finish
    W-->>A: signed bytes, manifest, exclusions, statistics
```

Top-level reads/builds are serialized, but signer replies are not top-level
operations. Queueing a reply behind its own waiting build would deadlock.
Replies must match both the operation ID and the Rust request handle.
Signer throws/rejections preserve their name/message across the protocol, not
their original object identity or stack.

A callback must not await another operation on the **same client**: that
operation is queued behind the build awaiting the callback. Use a separate
client for such work. A signer that never settles blocks its client's queue
until disposal; signer/network timeouts are caller policy, not an automatic
timeout or cancellation guarantee of this proof.

## Run the proof

Prerequisites: Rust 1.96+, the `wasm32-unknown-unknown` target, Node 22+, and
`wasm-bindgen-cli` **0.2.122**. The Wasm dependency is pinned to the CLI schema;
other versions require changing both together.

From this directory:

```sh
rustup target add wasm32-unknown-unknown
# Only if the matching CLI is not already installed:
cargo install wasm-bindgen-cli --version 0.2.122 --locked
npm ci
npx playwright install chromium firefox webkit
npm run build:bindings
npm run fixtures
npm test
npm run test:browser
npm run test:matrix   # capability matrix, see below
```

The independent Neon and Wasm workspaces are not built by root `cargo test`.
`fixtures` builds the existing signing addon, generates small and 64 MiB signed
assets with the repository's public TEST ONLY ES256 credentials, and checks
their full reports against the existing direct Node host. It requires no
external service and does not add signing functionality to Rust.
It also records the direct signer's exact COSE input/algorithm and exclusion
ranges, and exports the repository's public TEST ONLY key in PKCS#8 form for the
application-side WebCrypto test signer. Never substitute production credentials
in these generated fixtures.

### Capability matrix

`npm run test:matrix` ([`test/matrix.test.mjs`](test/matrix.test.mjs)) probes
every capability the Rust workspace implements through the Node and browser
entry points. Each probe asserts today's observed outcome, so the suite fails
when a gap opens or closes without its report
([`experiments/2026-10-17-vertical-slice-matrix.md`](experiments/2026-10-17-vertical-slice-matrix.md))
being updated. Gaps are classified by what closes them: JavaScript host code,
the Neon/Wasm glue, or the Rust bridge.

### SDK-to-SDK benchmark

After the builds and fixture generation above, `npm run benchmark:sdk` compares
public read/sign calls against an **already built** sibling `../c2pa-js` checkout
(relative to the repository root). It needs that checkout's installed Vite,
Node distribution/native addon, utilities distribution, and Wasm package.
The benchmark does not install or rebuild those dependencies. It bundles the
existing web facade and inline Worker into this proof's ignored generated
directory, preserving the SDK checkout and its existing build directories.

The current parity baseline is upstream c2pa-js `main` at `20531aa`, using
c2pa-rs **0.91.3** (Node SDK **0.9.10**, web SDK **0.15.4**).
Rebuild the sibling SDK's Node and Wasm release artifacts after updating it;
do not reuse binaries from an older checkout. Preparation verifies the lockfile's
c2pa version and records that version with checkout/package/artifact provenance.
Historical experiment reports retain their original versions and measurements.
See the [baseline refresh report](experiments/2026-10-16-sdk-baseline-refresh.md)
for rebuild commands and artifact hashes.

The command runs Node and all three browsers sequentially. Each SDK gets two
warmups and six alternating-order measured samples per size/operation.
Every sign output is validated by both readers outside signing time, and both
readers must reject tampering. Benchmark fixtures use the SDK's real unsigned
thumbnail plus a zero-padded 64 MiB variant and a conformant created-action
definition; they are separate from the original architecture-contract fixtures.
Only repository TEST ONLY credentials are used.

Results and provenance persist in ignored `results/sdk-*.json`; see
[SDK performance findings](experiments/2026-10-16-sdk-performance.md) for
medians, ranges, validation differences and ownership/build caveats. This is
a local warm baseline, not full compatibility or production performance proof.

An application uses the same calls with a different platform entry:

```js
// Node: "./src/node/client.mjs"; browser: "./src/browser/client.mjs"
import { createClient } from "./src/node/client.mjs";

const client = createClient();
try {
  const { report, stats } = await client.read(bytes, {
    settings: { verify: { ocsp_fetch: false } },
  });
  console.log(report, stats);
  // definition supplies the baseline title, instance_id, label, generator
  // and c2pa.created assertion; privateKey is an application-held P-256 key.
  const signed = await client.sign(unsignedJpeg, definition, {
    alg: "es256",
    certs: [certificateDer],
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, privateKey, data));
    },
  });
  console.log(signed.asset, signed.manifest, signed.exclusions);
} finally {
  await client.dispose();
}
```

Run the browser entry through an HTTP server; the acceptance runner supplies a
loopback-only server. The proof clock is restricted to signed 32-bit Unix
seconds by its small Wasm bridge; current dates and frozen fixture time fit.

## Acceptance and findings

`npm test` and `npm run test:browser` must actually load the native addon and
Wasm. No mocks substitute for the read/build boundaries. The shared read contract checks:

1. Complete report equality with the existing direct Neon host, including
   `Trusted`, signature and data-hash statuses.
2. Exact session read counts, bytes and advance counts across Node/Wasm.
3. Input snapshotting without detaching the caller's bytes.
4. Unsigned JPEG returning `null`.
5. Invalid settings and malformed asset rejection, followed by successful reads.
6. Last-byte tampering returning `Invalid`.
7. Two queued operations returning the correct independent reports.
8. Application timer progress during three repeated 64 MiB reads.
9. Disposal rejecting a pending operation and subsequent calls.
10. A second Worker continuing after the first client is disposed.

The [shared signing contract](test/signing.mjs) additionally proves:

- Full trusted read-back for small and 64 MiB signed assets, matching direct
  host reports, output/manifest lengths and hard-binding exclusions.
- Exact COSE signing input and algorithm equality with the existing direct
  signing host; randomized signatures need not be byte-identical.
- A caller-owned, non-extractable WebCrypto key works in all four environments.
- Input/definition/certificate snapshots, delayed callbacks and application
  task progress while a build awaits its signature.
- Synchronous throws, asynchronous rejections, invalid reply types/lengths,
  malformed definitions and subsequent successful operations.
- A 64-byte but invalid signature reads `Invalid`: reply-shape checks do not
  establish cryptographic correctness or make build success a trust verdict.
- Queued mixed reads/builds route correctly, and a second Worker can finish a
  different build while the first Worker's signer remains pending.
- Disposal rejects a pending build; both late signer success and rejection are
  safely handled without affecting another client.

The Node tests additionally exercise startup/crash and callback transport
failures, plus assert that neither late callback outcome posts to a disposed
port. These controlled port tests are not native-process crash tests.

The architecture works in Node and Chromium/Firefox/WebKit. Importantly,
**Neon loads inside a Node Worker without a Rust runtime or binding rewrite**.
Both adapters use the same pre-existing Rust sessions and the same JS host.
The 64 MiB asset needs 1,029 reads totaling 67,110,652 bytes, at most 64 KiB per
read, and 137 advances, identically across all four environments.

### Binary write-payload experiment

The browser adapter defaults to binary bulk write payloads.
`createClient({ transport: "json" })` selects the original boundary solely for
the experiment; it is not a proposed SDK configuration surface. Both paths use
the same Wasm binary, Rust session, JS driver, signer and fixtures.

`npm run test:browser` now runs the unchanged read/signing contracts against
**both** boundaries in all three engines, then runs
[the paired comparison](benchmarks/boundary.mjs): one warmup per size/transport and
four measured pairs per size, alternating which transport goes first.
Small and 64 MiB inputs yield 16 measured builds per browser, 48 total. Every
sample checks direct-host signing inputs, read-back report, output/manifest
lengths, exclusion ranges and identical request accounting outside the timed
build interval. Node remains the unchanged native reference.

Results include `transports` (both contract runs) and `comparison.samples`
(paired measurements). Browser build results expose a proof-only `boundary`
measurement:

- `wasmAdvanceMs`: Rust advancement, JSON construction/serialization and string
  transfer together, not isolated serialization time.
- `parseMs`: JavaScript `JSON.parse`.
- `payloadMs`: payload conversion/copy plus request normalization; binary uses
  an additional wasm-bindgen byte retrieval call.
- `metadataChars`, `writePayloadBytes`, `writes`: transport/accounting checks.

The local comparison reduced median large-build caller duration by about
6.7–8.5 times in all browsers; binary is retained as the default. Small builds
were too short/timer-quantized for strong performance claims. See
[paired measurements and caveats](experiments/2026-10-16-binary-transport.md).

### Performance interpretation

Ignored `results/{node,chromium,firefox,webkit}.json` records three warm measured
reads and three builds, task progress, caller/Worker duration and input/binary/source
fingerprints, plus the paired boundary comparison described above. The
checked-in [findings](experiments/README.md) summarize a local run.
Timing is **not** a pass threshold. The only scheduling assertion is that
application tasks actually run before the read completes.

The synthetic asset is JPEG framing plus a zero-filled tail signed using the
existing core. This exercises logical hashing, not realistic image metadata,
physical I/O, a legacy comparison or cold-start distributions. Caller time
includes input snapshot/cloning, queueing, report transfer and parsing;
Worker time includes session construction, hashing and report serialization;
build time also includes output assembly and the awaited application signer.
Their difference is not an isolated FFI cost.

Worker isolation does not remove copying: byte-array reads snapshot and clone
the entire asset; Blob/File reads instead materialize requested slices.
Large byte-array messages can still briefly occupy the calling thread.
No peak memory or frame-deadline guarantee is established.

## Deliberate non-goals and next trigger

No new domain validation, formats, identity/timestamp
support, network hosts, worker pools, custom schedulers, public cancellation
API or streaming-storage abstraction. No production publication.

New experiments are recorded in separate reports under
[experiments/](experiments/README.md), with reproduction, acceptance evidence and
measurement limitations. The [File/Blob experiment](experiments/2026-10-16-file-blob-memory.md)
compares byte-array and slice-backed input latency and sampled process memory.

The binary experiment identifies a large avoidable binding cost, not the cause
of every remaining native/browser difference. The File/Blob follow-up measures
latency and sampled RSS, not exact peak/retained memory or isolated copying cost.
Browser signing and Node buffered output still hold entire outputs in memory;
Node also supports direct file output. wasm-bindgen still copies payload
bytes. No core async conversion
is needed. Do not add cooperative Worker
scheduling without a required message/progress behavior that fails a test.
