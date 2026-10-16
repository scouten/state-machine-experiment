# Shared JavaScript host over Wasm and Neon

## Proposal and scope

Use one JavaScript facade, Worker protocol and session-driving loop in both
environments. Run that loop in a browser module Worker over Wasm, or a Node
`worker_threads.Worker` over Neon. Rust remains synchronous and sans-I/O.
Neither Tokio nor a custom scheduler is required for this example.

This is a **read-only architecture proof**, not a replacement SDK or a legacy
API migration. Reading is sufficient to exercise request/reply transport,
signature and hard-binding validation, settings, reporting, thread isolation
and lifecycle end to end. Signing is used only to generate fixtures with the
existing builder; a shared signing facade/callback bridge is not proven here.

The branch starts from `main` at `97fac9b`. No migration-branch changes or domain
features were copied. The original experimental worktree remains untouched.

## Architecture

```mermaid
flowchart TB
    App["Application: await client.read(bytes)"]
    Client["Shared JS Client<br/>snapshot, IDs, errors, disposal"]
    Service["Shared Worker service<br/>serialized operations"]
    Drive["Shared JS host loop<br/>advance / answer / fulfill / finish"]
    Browser["Browser adapter<br/>synchronous wasm-bindgen calls"]
    Node["Node adapter<br/>synchronous Neon calls"]
    Session["Existing NodeSession<br/>portable plain-data bridge"]
    Reader["FileReadSession + C2PA reader"]
    App --> Client
    Client -->|"postMessage: clone bytes, no transfer"| Service
    Service --> Drive
    Drive --> Browser & Node
    Browser --> Session
    Node --> Session
    Session --> Reader
```

The application and service are in different execution realms. Platform files
only start Workers, normalize message/error/termination APIs and translate
binding values. The **same imported modules**, not parallel implementations,
own these behaviors:

| Module | Shared responsibility |
| --- | --- |
| [client.mjs](shared/client.mjs) | Public Promise API; request identity; input snapshot; reply/error handling; disposal |
| [service.mjs](shared/service.mjs) | Worker command dispatch and serial operation queue |
| [drive.mjs](shared/drive.mjs) | Session progression; byte ranges; clock/length replies; request accounting; cleanup |
| [contract.mjs](test/contract.mjs) | Identical acceptance checks in Node and all three browsers |

The existing `NodeSession` name describes its original consumer, not a runtime
dependency. It already compiles to Wasm. The small standalone
[Wasm crate](wasm/src/lib.rs) exposes that same synchronous session; it does not
use the existing browser async host or duplicate C2PA logic. The
[naming proposal below](#proposed-neutral-session-name) records how to make that
shared role explicit; the rename/extraction is not part of this proof.

Wasm serializes new request metadata as JSON. Neon returns objects and expects
Buffers for byte replies. Adapters normalize those differences. This is a
deliberately simple boundary, not a claim of optimal serialization performance.

### Proposed neutral session name

**Proposal, not yet implemented:** rename `NodeSession` to `ReadSessionBridge`
and move its shared request/reply surface into a runtime-neutral
`contentauth-c2pa-session-bridge` crate when promoting this proof into a shared
SDK.

The current [session wrapper](../contentauth-c2pa-node-compat/src/session.rs)
adapts `FileReadSession` for a binding boundary. It selects the supported format,
parses compatibility settings, maps opaque engine request IDs to numeric host
handles, reports each new request once, translates replies, and returns the
compatibility reader result. It does not call Node APIs, use Neon, perform I/O,
spawn threads, or schedule work. Byte reads, length, clock and OCSP transport are
host responsibilities, not inherently Node-specific operations.

The Node association is historical and API-shaped: the wrapper originated in
the Node compatibility crate, accepts c2pa-node-style format/settings arguments,
and maps a missing manifest to `None` for the JS `null` result. The proof's
browser adapter now uses that same contract. Portability does not make these
compatibility choices part of the generic engine.

`ReadSessionBridge` names both the workflow and the responsibility: adapting a
reader session into a plain-data binding contract. `NodeSession` suggests a
runtime restriction that does not exist; `ReadSession` alone would obscure the
distinction from the underlying reader sessions. The bridge is not a Worker,
host driver, scheduler or new validation engine.

The follow-up should:

- Move the wrapper and its `PendingRequest`, `Reply` and `Step` vocabulary
  together, with their protocol tests. Keep C2PA and compatibility policy above
  the generic state-machine engine.
- Give shared settings/report/error types neutral ownership where needed.
  Do not leave the shared bridge depending on a Node-specific facade or copy
  those types into a second implementation.
- Update the Neon and Wasm adapters, callers, tests and documentation together.
  Preserve constructor, request, result and error behavior; this is an ownership
  and naming change, not a new SDK behavior or expanded format support.
- Re-run the identical Node/browser contract and existing Node regression tests.
  No compatibility alias is needed for this experimental Rust API.

Node-specific code should remain in the Neon binding and Node host/Worker
adapter; browser-specific code should remain in the Wasm binding and browser
host/Worker adapter. The shared JS driver continues to use the same bridge
protocol in both.

### Reuse beyond JavaScript

The proposed bridge is language-neutral, not merely shared between two
JavaScript runtimes. A Python, Swift, Kotlin or C# host could use the same
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

Only JavaScript consumers are proven by this experiment. Other-language
bindings and a universal ABI are not implemented or required for the proposed
rename. Prove a concrete additional consumer before introducing further
abstractions.

The following is a **proposed ownership model**, not the current dependency
graph. Solid paths have existing JavaScript consumers; the dotted path is a
possible, unproven additional consumer. The neutral crate and rename are not
implemented.

```mermaid
flowchart TB
    JS["Shared JS host<br/>browser and Node Workers"]
    Wasm["Browser binding<br/>wasm-bindgen"]
    Neon["Node binding<br/>Neon"]
    Other["Possible other-language host + adapter<br/>not implemented or tested"]
    Bridge["PROPOSED: ReadSessionBridge<br/>contentauth-c2pa-session-bridge<br/>plain-data requests / replies"]
    File["FileReadSession<br/>typed Rust session"]
    Rust["Existing Rust host<br/>direct typed access"]
    JS --> Wasm & Neon
    Wasm --> Bridge
    Neon --> Bridge
    Other -.-> Bridge
    Bridge --> File
    Rust --> File
```

## Ownership and execution

- One Worker per client. Workers are reused; top-level operations are queued.
  Pending requests within one operation can be answered as a batch.
- Native handles and Wasm objects never cross Worker boundaries. Results are
  plain reports, not remote reader objects.
- `read()` copies input before its first await, then uses structured cloning.
  Caller buffers remain attached and mutation cannot change a queued read.
  This costs memory and synchronous caller work proportional to input size.
- This proof accepts in-memory JPEG bytes only. It does not promise streaming
  input, constant memory, zero-copy transfer or free result transport.
- Successful `finish` consumes the Rust session. Wasm wrappers are explicitly
  freed in `finally`; Neon error handles become eligible for isolate GC.
  Client disposal terminates its Worker, releasing that isolate's resources.
- Disposal rejects pending calls. It is **abrupt termination**, not graceful
  cancellation. There are no file writes or network operations to clean up.
- No periodic task yields are inserted. A busy Worker can delay its own control
  messages; the application remains on a separate event loop. Responsive
  cancellation/progress or concurrent shared-Worker execution is not promised.
- Only offline reading is covered. OCSP and future unrecognized host requests
  fail explicitly. Core validation remains Rust-owned.

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
```

The independent Neon and Wasm workspaces are not built by root `cargo test`.
`fixtures` builds the existing signing addon, generates small and 64 MiB signed
assets with the repository's public TEST ONLY ES256 credentials, and checks
their full reports against the existing direct Node host. It requires no
external service and does not add signing functionality to Rust.

An application uses the same calls with a different platform entry:

```js
// Node: "./node/client.mjs"; browser: "./browser/client.mjs"
import { createClient } from "./node/client.mjs";

const client = createClient();
try {
  const { report, stats } = await client.read(bytes, {
    settings: { verify: { ocsp_fetch: false } },
  });
  console.log(report, stats);
} finally {
  await client.dispose();
}
```

Run the browser entry through an HTTP server; the acceptance runner supplies a
loopback-only server. The proof clock is restricted to signed 32-bit Unix
seconds by its small Wasm bridge; current dates and frozen fixture time fit.

## Acceptance and findings

`npm test` and `npm run test:browser` must actually load the native addon and
Wasm. No mocks substitute for the read boundary. The shared contract checks:

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

The Node tests additionally exercise facade startup/crash error propagation
through a controlled port failure. This is not a native-process crash test.

The architecture works in Node and Chromium/Firefox/WebKit. Importantly,
**Neon loads inside a Node Worker without a Rust runtime or binding rewrite**.
Both adapters use the same pre-existing Rust session and the same JS host.
The 64 MiB asset needs 1,029 reads totaling 67,110,652 bytes, at most 64 KiB per
read, and 137 advances, identically across all four environments.

### Performance interpretation

Ignored `results/{node,chromium,firefox,webkit}.json` records three warm measured
reads, task progress, caller/Worker duration and input/binary/source
fingerprints. The checked-in [findings](findings.md) summarize a local run.
Timing is **not** a pass threshold. The only scheduling assertion is that
application tasks actually run before the read completes.

The synthetic asset is JPEG framing plus a zero-filled tail signed using the
existing core. This exercises logical hashing, not realistic image metadata,
physical I/O, a legacy comparison or cold-start distributions. Caller time
includes input snapshot/cloning, queueing, report transfer and parsing;
Worker time includes session construction, hashing and report serialization.
Their difference is not an isolated FFI cost.

Worker isolation does not remove copying: each read snapshots and clones the
entire asset. Large messages can still briefly occupy the calling thread.
No peak memory or frame-deadline guarantee is established.

## Deliberate non-goals and next trigger

No new domain validation, formats, compatibility shims, identity/timestamp
support, network hosts, worker pools, custom schedulers, public cancellation
API or streaming-storage abstraction. No production publication.

The next useful extension, if selected, is signing through this same Worker
service with a purpose/operation-scoped caller callback. File/Blob sources
could follow when whole-input cloning becomes an actual workload constraint.
Neither requires making the core asynchronous. Do not add cooperative Worker
scheduling without a required message/progress behavior that fails a test.
