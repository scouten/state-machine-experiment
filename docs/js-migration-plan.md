# c2pa-js migration: implementation and proof plan

Status (2026-10-15): binding feasibility is the active workstream. M0 and the
defined M1 slice are implemented; M2/M3 remain partial on the historical
full-parity roadmap, not the current exit gate. The M0 browser oracle executes
the legacy SDK, not the state-machine bindings. This document does not claim a
full-parity shim already exists.

## Current priority: binding feasibility, not Rust feature parity

As of 2026-10-14, the active experiment is to determine whether browser and
Node wrappers can effectively expose the state-machine implementation's
**existing** capabilities and accommodate its planned architecture. Full
c2pa-js parity remains a long-term compatibility goal, not the prerequisite
or progress measure for this experiment. The M0-M5 sequence below records the
broader migration roadmap; it must not pull missing domain functionality into
the binding workstream.

### Ownership and scope

| Layer | Responsibility | Evidence |
| --- | --- | --- |
| Shared Rust core | Parsing, encoding, cryptography, validation, format handling and domain workflows | Existing native tests; native differential tests for domain changes |
| Shared compatibility projection | Translate Rust results into the legacy report contract once for both bindings | Native projection tests; classify missing semantics separately |
| Wasm/Neon boundary | Requests/replies, bytes, settings, result/error transport and native-handle lifetime | Real binding tests for representative shapes and failures |
| Browser/Node host | Blob/file I/O, fetch policy, clock, signing/timestamp callbacks, scheduling and cancellation | Environment-specific integration tests |
| JS compatibility facade | Legacy names, types, defaults, Promise/synchronous behavior and lifecycle | Adapted or unchanged upstream tests applicable to available Rust capabilities |

Do not implement a missing format, ingredient/history rule, builder operation
or cryptographic capability merely to make an upstream JS test pass. Record it
as a Rust dependency. Likewise distinguish an existing Rust result that the
legacy projection cannot yet express from a broken binding. Never remove a
reporting guard, drop unsupported fields or invoke legacy automatically to make
an operation appear supported. A future native-result API can expose richer
Rust results, but its public contract must be designed explicitly rather than
smuggled into a compatibility method.

### Binding-focused implementation sequence

1. Map existing read/build session requests, replies and results to browser and
   Node entry points. For each gap record: implemented, missing binding,
   missing shared projection, blocked by core, or planned/not implemented.
   Link to source and representative proof; count capabilities, not repeated
   browser executions.
2. Close missing binding/host paths for existing Rust functionality in coherent
   slices. Reuse `FileReadSession`, `FileBuilderSession`, the shared projection
   and resource resolver. Preserve the browser `Blob`/`Platform`/`AsyncSigner`
   adapters and Node's JS-owned `advance`/`fulfill` loop unless concrete binding
   evidence warrants a change. No new core feature is implicit in this step.
3. Prove boundary fidelity and host behavior: exact byte ranges and ownership,
   typed results/settings/errors, pending-request identity, partial/out-of-order
   fulfillment, concurrent operation isolation, callback rejection, source
   failure, cleanup/disposal and retry. Test each at its owning layer; do not
   duplicate the entire domain test matrix across environments.
4. Evaluate effectiveness, not just a successful call: measure host crossings,
   copying, bounded reads, event-loop responsiveness and retained memory for a
   representative read/build workload. Large synchronous Rust work may still
   block a calling thread; sans-I/O does not itself imply responsiveness.
   Compare inline/Worker and Node hosting options before selecting policy.
5. Reassess architectural extension seams using the existing typed request
   protocol: document how a future workflow, handler or host operation reaches
   each binding, how unsupported requests fail, and which adapters/tests change.
   Planned functionality is not reported as available. Do not implement
   speculative extension frameworks.

**Binding experiment exit:** real Wasm and Neon wrappers exercise the agreed
existing read/build capability set, preserve boundary contracts and host
ownership, have representative failure/concurrency/lifetime proof, and have
measured scheduling/copy/memory costs with explicit limitations. Every selected
capability has a binding result or a clearly attributed blocker; planned
extensions have an adaptation path. Missing Rust features do not fail this
feasibility gate, but missing bindings for selected available features do.

**Verification cadence:** exhaustive domain/projection proof stays native.
Run targeted binding/environment tests for each slice. Run the full applicable
browser/Node/upstream and installed-package matrix at a binding milestone or
when its shared plumbing changes; refresh evidence required by provenance
checks, but do not treat repeated executions as newly ported functionality.
The 249-case ledger continues to track eventual full compatibility separately.
Legacy remains an explicit caller-selected rollback, with no default promotion,
publication, contraction or automatic fallback.

### Branch cleanup and retained dependencies (2026-10-15)

Removed the standalone ingredient manifest-link validator, parser/status wiring,
its eight core tests, two differential tests, fixture generator, six fixture
files, one Node test and its conformance-only direct reader dependency.
Linked-history reports still reject explicitly. This restores the core
capability boundary before that experiment, not a new claim that linked assets
are fully validated. A pre-cleanup recovery snapshot is held outside the
repository in the session artifacts, together with an isolated binary-capable
reapplication patch verified by `git apply --check`. The patch restores code
and dedicated fixtures/tests only, not the old documentation/scope claims.

The remaining Rust changes were classified rather than reverted by directory:

| Retained work | Why it belongs in the binding experiment |
| --- | --- |
| Resource decoding/retention and verified signer/timestamp metadata | Supply the bytes and result fields already exposed by the retained browser/Node demonstrations; JS must not decode or reconstruct them |
| Claim extension retention and owner-qualified status/provenance metadata | Preserve information at the shared Rust-to-legacy projection seam instead of duplicating report semantics in JS |
| Explicit `verify_trust` policy and Context plumbing | Implement an already exposed caller setting in Rust; removing the policy alone would misrepresent the retained setting |
| Exact duplicate icon-reference suppression and disabled-OCSP reporting correction | Coupled correctness fixes for retained resource/report/settings behavior; not a new domain workflow |
| Shared legacy projection, ingredient metadata and unsupported-history guards | Existing compatibility support used by both bindings; retained, not expanded as a new feature workstream |
| Earlier detached sessions, standard JPEG remote discovery and format selection | Already integrated capabilities behind retained host/binding demonstrations; no broad historical commit rollback |
| Native/browser/Node/package tests and test-only performance instrumentation | Preserve regression and feasibility evidence; routine checks are targeted, not repeated domain qualification in every runtime |

These are retained dependencies of the working prototype, not a claim that all
core changes are binding code. New domain validation, formats and builder
features belong in separate core work. Tests remain available, but execution
counts are evidence totals, not capability completion percentages.

Cleanup verification: 302 reader units, 68 shared projection units, native
integration/doc tests, 39 actual reader-addon tests, 33 signing-addon tests,
the retained real-SDK detached-resource differential test and 36 JS tests pass.
TypeScript checking, a fresh release Wasm/wasm-bindgen build, both portable
Wasm target checks, workspace all-feature/all-target Clippy and pinned formatting
checks pass. JS tests were rerun after rebuilding the stale Wasm cache.
The broad browser, installed-package and performance matrices were not rerun:
their earlier counts below are historical evidence, not post-cleanup passes.

## Target and compatibility contract

Build a JS SDK on the sans-I/O state machines, with compatibility entry points
that let applications migrate without rewriting their reader/builder calls.
Cover browser and Node, reading and writing, public types and package exports,
observable errors, settings, resources, and lifecycle behavior.

Freeze the first oracle to upstream
[`contentauth/c2pa-js` commit `3c642db3e566f20ede9442090d1d414f424bcea1`][upstream].
At this revision `@contentauth/c2pa-web` reports version `0.15.3`.
Record the package versions, lockfile, SDK/Wasm artifacts, test inventory, and
fixture hashes together. Track newer upstream revisions separately rather than
changing the oracle underneath an implementation milestone.

Full parity means the pinned public contract passes on the new backend without
legacy-engine assistance. Passing a JPEG subset is a prototype milestone, not
full parity. Production suitability additionally needs corpus, robustness, and
performance evidence; SDK test parity alone does not establish those.

## Performance: cost of crossing the host boundary

Treat host-boundary overhead as a first-class migration question, not an
assumption. The state-machine path may make multiple JS/Wasm-to-host requests
for asset ranges, signatures, timestamps, or network responses, while the
previous SDK may batch some of that work differently. Measure the observable
cost before optimizing or setting a performance budget.

For each comparison, run the same operation on the pinned legacy SDK and the
state-machine backend with identical browser/version, asset bytes, settings,
trust anchors, and signer. Instrument the host adapters on both sides to record
per operation:

- Number of host-boundary calls, grouped by operation (asset read, sign,
  timestamp, remote fetch); distinguish a Rust session step from an actual
  JS/host crossing.
- Bytes requested and returned per asset-read call, total bytes transferred,
  and time spent awaiting host replies.
- End-to-end operation duration after Wasm/module and fixture setup. Report
  warmed-run median and p95, with cold initialization measured separately.
- Optionally, time to the first host yield and event-loop delay while the
  operation is in flight; do not infer responsiveness from total duration.

Start with two small browser comparisons:

1. **Unsigned JPEG read:** use the same unsigned fixture and verify both APIs
   return the same absent-manifest result. This is the low-work baseline.
2. **Signed JPEG validation:** use one fixed, trusted JPEG with a hard binding
   and verify equivalent validation outcomes and manifest identity. This
   exercises the full asset-byte read path.

For each, first measure the natural browser host and record its call count,
latency, and bytes. Then repeat with a deterministic per-reply delay in the
test host (including a zero-delay control) to expose how much added latency is
amplified by additional crossings. Keep artificial-delay results separate from
native timings. Add asset-size variants only after these two cases produce a
reproducible comparison; signing comparisons belong in M4 once the same
definition and signing behavior are supported on both backends.

Run the initial baseline in Chromium for quick iteration, then run the selected
comparison on Chromium, Firefox, and WebKit before making a cross-browser
performance claim. Keep timing results as evidence, not flaky pass/fail
assertions. Assert deterministic request counts, byte totals, and result
equivalence in CI. Choose any duration or regression budget only after reviewing
the baseline distributions and measurement noise.

The initial two-case harness is now implemented as
[`test:performance`](../c2pa-js-state-machine/README.md#host-boundary-performance-experiment).
It asserts outcome, read-count, and byte-total baselines and records natural,
zero-delay, and 2 ms/read delay series with raw samples and median/p95.
The comparison now includes legacy Worker, state-machine inline,
state-machine module Worker, and a test-only bounded read-ahead Worker using the
same bytes/settings/clock, with four-path
order rotated across samples. Worker location is matched, not the Wasm code,
loader or I/O model; this is not an isolated FFI measurement.
Legacy's synchronous whole-Blob reads require a
test-only busy wait for synthetic delay; state-machine's asynchronous slice
reads await timers. Read-service duration is reported rather than misleadingly
calling legacy synchronous time "await time." Length/clock requests and Worker
control messages are counted separately from byte reads. Test-only Worker-side
Blob instrumentation returns one aggregate packet per operation and a
Worker-local execution span, excluding caller queues/clone and packet delivery.
The new Worker read uses one command and one reply despite 10/15 Blob reads
inside its realm. Exact schema-v3 checks reject incomplete/invalid timing,
read/byte, or message evidence. Larger-asset variants, event-loop/memory proof,
and pure crossing/copy cost isolation remain follow-ups;
no chunk-size or scheduling optimization is made by this measurement slice.

The test-only read-ahead host keeps one operation-local 4 KiB window for
requests of 64 bytes or fewer; large manifest/hash reads bypass unchanged.
All three browsers prove unchanged logical requests and full signed/tampered
projections, malformed-input rejection, and physical-read reductions from 10 to 1
(unsigned) and 15 to 4 (signed). Physical bytes rise from 38 to 4,096 and 88,525
to 92,559 respectively; the report records this trade-off rather than presenting
cache hits as eliminated logical boundary calls. Unit tests cover exact ranges,
EOF/empty handling, eviction, source/output isolation, failures/short reads and
concurrent requests. Cache-window occupancy is not whole-process peak memory.
No production cache is enabled. A broader metadata/layout corpus, large assets,
memory/response-time evidence and window/threshold choices remain gates.

Initial measurements on 2026-10-13 show the current legacy backend reads the
whole Blob once; state-machine reads 10 ranges totaling 38 bytes for the
unsigned fixture and 15 ranges totaling asset length plus 38 bytes for the
signed fixture. Many are tiny JPEG header reads, not hashing chunks. Synthetic
per-read delay amplifies the serial state-machine path's latency. Natural
timings vary by browser (the trusted signed state-machine case is slower in
Chromium/WebKit but faster in Firefox in the initial run), so these observations
do not establish an overall performance ranking. Investigate host read-ahead or
coalescing before choosing a chunk-size change. The matched Worker experiment
confirms browser-dependent rankings rather than one overall winner; its measured
tables and caveats are in the linked experiment README. Both new paths still
amplify per-read injected latency. No chunk or scheduling changes were made.

## Existing building blocks and gaps

- [WasmReader](../contentauth-c2pa-js-compat/src/web.rs) already exposes
  `fromBlob`, `activeLabel`, `manifestStore`, `activeManifest`, and `json`.
  It drives the same synchronous file session as the other hosts.
- [WasmBuilder](../contentauth-c2pa-js-compat-sign/src/web.rs) exposes
  `fromJson` and async `sign`, with a JS-owned signer and byte-array outputs.
- The [Node reader](../c2pa-node-compat-addon/index.mjs) and
  [Node builder](../c2pa-node-sign-addon/index.mjs) already put async work in JS
  around synchronous session functions. Reuse these drivers and error contracts.
- [Manifest reporting](../contentauth-c2pa-js-compat/src/manifest_store.rs)
  currently projects assertions as labels, not the complete assertion objects
  expected by c2pa-js. Richer reporting must originate in the reader's result,
  then flow through the shared projection and both bindings.
- [Context parsing](../contentauth-c2pa-js-compat/src/context.rs) recognizes only
  a settings subset. Compatibility requires the upstream JS Context resolution,
  casing, defaults, precedence, and trust-policy behavior, not merely passing an
  arbitrary settings object through JSON.
- Browser format selection currently accepts JPEG only. Browser OCSP is declined
  by `WebPlatform`; remote manifests, fragmented assets, and resource retrieval
  are documented gaps.
- Existing CI compiles the browser bindings for Wasm. It does not execute them in
  a browser. Native async tests are useful lower-layer proof, not a replacement
  for that gate.

The existing native baseline was run successfully during this planning work:

```sh
cargo test -p contentauth-c2pa-js-compat -p contentauth-c2pa-js-compat-sign
```

## Ownership and API shape

Keep three layers distinct:

1. **Engine and domain sessions:** synchronous Rust; no filesystem, fetch,
   browser objects, workers, or async runtime. Add missing domain capabilities
   here only when they genuinely belong to validation/building.
2. **Platform adapters:** browser Blob/clock/network/signer operations and Node
   range reads/writes/fetch. Container details remain in format handlers.
3. **JS API and compatibility facades:** factories, settings resolution,
   Promise shapes, errors, resource lifetimes, and old method names.

The new API should expose host control without forcing ordinary callers to
drive every request manually: a client for read/build operations, with explicit
host capabilities, and an advanced session adapter where needed. Reuse the
existing async browser host for the first vertical slice; do not first rewrite
it as a second JS orchestration loop. A later flattened browser session bridge
can reuse the Node request/reply model when custom JS hosts require it.

PROPOSED implementation locations:

- `c2pa-js-state-machine/`: a standalone TypeScript package containing the new
  client, web/Node compatibility entry points, and contract harness.
- `contentauth-c2pa-web-bindings/`: a thin browser `cdylib` packaging the existing
  read/sign implementations and generated JS glue into one SDK artifact.
  Verify generated exports rather than assuming an `rlib` or `cargo check`
  produces a loadable browser SDK.

Use Vite/Vitest with Playwright's browser provider, matching upstream's existing
runner rather than introducing a second browser test framework. Keep this
package's JS tooling isolated from the portable Cargo members. Pin the
wasm-bindgen CLI to the resolved library version. A new workspace member must
still pass the repository's Wasm/MSRV/lint checks.

## Compatibility shims and incremental migration

Provide separate web and Node compatibility entry points over the new client.
The browser facade must preserve `createC2pa`, static `Reader`/`Builder`
constructors, deprecated reader/builder factories, and the inline and Worker
entry points. The Node facade must preserve its synchronous definition-editing
methods alongside async reads/signing, signer adapters, and file/buffer shapes.
Use the pinned declarations and export inventory as the authoritative list.

Resolve the backend explicitly when creating a client/runtime. Start with
legacy as the migration default; callers opt into state-machine for a tested
workflow. Bind Reader/Builder handles immutably to that backend, context, and
runtime. Mixed-backend objects must be rejected rather than silently coerced.

The compatibility factory can inject either backend into the same tests and
application example. Keep resource URLs separate for each backend: an existing
c2pa-js `wasmSrc` cannot be treated as a state-machine Wasm binary. Preserve
`workerSrc`, precompiled-module loading, CSP behavior, and loader errors at the
compatibility boundary.

Preserve observable details, not just method names:

- `null` for a missing manifest, versus rejection for malformed/unsupported
  input; browser error strings versus Node Error names and messages.
- Promise versus synchronous return behavior, optional fields versus `null`,
  array ordering, byte-array/Buffer/Blob types, and cloned versus borrowed data.
- Global and per-call settings, independent Context instances, cached context
  resolution, and precedence in deprecated factories.
- `free`/`dispose`, post-disposal calls, Worker termination, and hidden
  Reader/Builder internals during enumeration/serialization.
- Public TypeScript assignability and package subpath/resource exports, not
  only successful runtime imports.

Do not catch a state-machine failure and retry on legacy automatically. In
particular, signing or writing must not run twice. An explicit capability
decision may select legacy *before* a workflow starts, but record that selection;
such a result never counts as state-machine parity. Unsupported features must
remain identifiable, not become plausible empty resources or manifest fields.

This requested compatibility boundary is intentional even though the internal
Rust prototype permits breaking changes. Preserve the JS migration contract
while updating internal callers normally; do not add engine-wide legacy shims.

## Implementation sequence and exit gates

### M0: freeze the contract and build a dual-backend harness

Implemented in [c2pa-js-state-machine](../c2pa-js-state-machine/README.md):
249 test declarations across 15 files, 33 exported source surfaces, source and
published-type fingerprints, and five unchanged legacy reader tests passing in
Chromium. Initially all 249 state-machine declarations were explicitly unported;
M1 now proves five while retaining the remaining 244 in the ledger.

Inventory public exports/declarations and every upstream test across web, Node,
types, and utilities. Include inline loading, Worker sanitization, settings,
signers, identity assertions, and Trustmark, not just reader tests.

Adapt upstream's [test fixture injection][test-fixtures] to supply legacy or
state-machine factories. Share fixtures, contexts, clock, and mock responses;
leave test bodies and expectations intact wherever possible. Isolate the
upstream oracle as a development dependency/build artifact, never as an
unadvertised runtime implementation of the new backend.

Maintain a machine-readable contract ledger with upstream revision, file/test
identity, fixture hashes, platform, milestone, backend, status, and blocker.
Statuses distinguish passing, failing, and not ported. A missing/filtered test
does not pass. Document unavoidable harness-only changes and retain upstream
MIT licensing and copyright notices for copied tests/assets.

**Exit:** the pinned legacy runner passes the selected original tests; every
upstream test is accounted for, and the new backend's initial failures are
visible. No xfail/skip count can disappear from the parity denominator.

### M1: a browser-executed JPEG read/sign vertical slice

Implemented in [the inline prototype](../c2pa-js-state-machine/README.md) and
[`contentauth-c2pa-web-bindings`](../contentauth-c2pa-web-bindings/README.md).
The five unchanged upstream cases and ten separate milestone cases run in
Chromium, Firefox, and WebKit (45 executions). Evidence fingerprints the actual
generated artifacts and inputs. The facade preserves the selected Reader
contracts; its baseline raw ES256 signer is intentionally not yet the legacy
COSE-producing signer API. Full reporting, Worker hosting, distribution, and
remaining builder/shim parity stay in later milestones. The frozen clock is
2026-09-01, inside the public signing fixture's validity window.

Build real Wasm and generated JS, load it through the proposed package, and run
on Chromium, Firefox, and WebKit. First prove direct/inline execution; establish
a Worker host for the compatibility default before claiming Worker parity.
Exercise packaged resources rather than mocking the Wasm module.

Implement only the facade behavior required by this slice: initialization,
format sniffing, reader lifecycle, byte conversion, precise error mapping, and
baseline signing. Use a checked-in test certificate/key through WebCrypto,
importing the private key as non-extractable; signing returns COSE-compatible
ES256 bytes. Freeze both backends' clocks inside the fixture validity window.

Required proof:

- The original web reader tests starting at lines 54, 64, 302, 408, and 420
  pass unchanged: unsigned asset, size rejection, error propagation, freeing,
  and non-enumerable internals. Their assertions remain the upstream oracle.
- A new baseline JPEG signs in the browser, reads back `Trusted` with the
  configured signing root, and exposes the generated asset/manifest byte types.
  A no-anchor read and a tampered-asset read demonstrate that trust/validation
  have not been replaced with a success-shaped projection.
- Read legacy-signed output through the new backend and new-signed output
  through legacy. Compare binding semantics and validation, not random ECDSA
  signature bytes. Label known full-reporting differences as M2 blockers.
- Two reads and two builds genuinely interleave across suspended host requests.
  Instrument requests/callbacks; verify no duplicate signing callbacks for a
  given signing purpose, and rejection does not poison the next operation.
- Signer failure, Blob failure, invalid definition, missing requested timestamp
  service, initialization failure, and disposal leave no unhandled rejection or
  live Worker/resource after teardown. Add timestamp success with a deterministic
  local TSA fixture when that service adapter is introduced.
- The existing Rust JS read/sign suites and portable CI checks remain green.

**Exit:** all mandatory M1 cases pass in all three browsers with zero skipped
mandatory cases. Publish a reproducible demo and a report explicitly calling
this a JPEG prototype, with the M2+ ledger still visible.

### M2: complete reader reporting, settings, and resources

Extend reader result producers before expanding the shared manifest projection.
Decode assertion values/kinds, ingredient relationships and validation results,
signature metadata, thumbnails/resources, and CAWG reporting. Resolve resources
to exact bytes through the same host/session boundary.

Implement upstream Context semantics, including separate signing/identity trust,
trust-disabled behavior, per-operation settings, and resolution caching.
Settings that cannot yet be honored must not silently behave like a supported
setting when the application explicitly selects the new migration facade.

**Exit:** the unchanged upstream full-store golden tests pass, including trust
enabled/disabled and independent Contexts. Resource tests compare complete byte
arrays. Node and browser agree on the shared report for the same asset/settings.
In particular, do not reduce upstream's `toEqual(ManifestStore)` tests to checking
only `validation_state` or assertion labels.

**In progress:** the reader now decodes CBOR assertion payloads and v2
created-assertion relationships. The inline facade accepts separate signing and
CAWG trust settings and rejects unsupported trust-verification settings.
Active-manifest validation-result buckets are projected and checked in Rust and
browser tests. Browser proof covers this subset; full-store equality, ingredients,
signature metadata, exact validation-result parity, thumbnails, and resource
bytes remain open.

### M3: network, formats, and runtime/distribution parity

Add remote-manifest and detached-manifest session capabilities, then host
transports; implement fragmented BMFF and the remaining upstream format matrix
through format handlers. JPEG, DASH/BMFF, and JXL fixtures already appear in the
upstream browser tests; derive the complete matrix from the pinned SDK instead
of assuming those three are exhaustive.

Provide controlled browser OCSP/remote fetch behavior with URL policy,
response limits, cancellation/timeouts, and deterministic local test servers.
Test failure, denial, CORS, and retry paths; do not rely on a public responder.
Keep HTTP outside the domain engine.

**In progress:** `FileReadSession` accepts detached manifest-store bytes and
surfaces a format-reported remote URL when `fetch_remote_manifests` is enabled.
The async compatibility host forwards that request through
`Platform::remote_manifest`; hosts without transport fail explicitly. The
inline JS reader now accepts detached manifest-store bytes and passes them
through the Wasm binding into that same session. The JS builder now also has an
explicit detached-output path: it skips placeholder reservation and encodes an
empty exclusion list so the hard binding covers the complete asset. Browser
proof strips the fixture's C2PA APP11 segment, verifies the output asset is
unchanged and has no active embedded manifest, then reads the detached store as
`Trusted`; a changed asset reports `Invalid`, and malformed detached bytes are
rejected.

JPEG now reports standard XMP `dcterms:provenance` pointers using a
namespace-aware XML parser, with DTDs disabled and explicit malformed/ambiguous
packet rejection. Extended XMP remains unsupported. The inline facade accepts
optional remote-host options: an exact-origin allowlist, positive byte limit,
deadline, and optional caller abort signal. The Rust/Wasm adapter invokes that
host only for the session's remote request; HTTP remains in JavaScript.
Fetching omits credentials/referrer, forbids redirects, checks streamed decoded
bytes (not only Content-Length), and aborts on deadline or cancellation.
Loopback HTTP origins are allowed only when explicitly listed, for local tests;
other origins require HTTPS. Embedded/detached stores take precedence, remote
fetching is still off by default, and failed fetches reject without fallback.
Real loopback-server browser proof covers trusted remote reads, tampering,
precedence, denial, redirects, HTTP/size/malformed failures, header/body
deadlines, cancellation, cross-origin CORS denial/success, and explicit retry
in all three browsers. The test servers use ephemeral loopback ports and shut
down with the test runner.

Browser OCSP now uses an opt-in JavaScript POST host with the same origin,
streamed-byte, deadline, redirect, and cancellation controls. Explicitly
authorized HTTP origins are permitted for OCSP because signed DER, not HTTP,
authenticates the response. CORS and mixed-content rules still apply. The host
sets `application/ocsp-request` and accepts `application/ocsp-response`; Rust
constructs the request and verifies the response. Browser proof uses ephemeral
TEST ONLY certificates and genuine OpenSSL-signed responses, with SHA-256
CertIDs and a fixture clock strictly inside the response window. It proves
default-off/no-request behavior, non-revocation, authenticated revocation,
malformed DER, destination/CORS/HTTP/redirect/size denial, header/body deadlines,
in-flight abort, and retry. Unavailable or unauthenticated responses record
`signingCredential.ocsp.inaccessible` without invalidating the asset; authenticated
revocation does invalidate it, preserving the core's existing policy.

The shared JS/Node format selector now uses the host-side registry for JPEG and
TIFF/BigTIFF/DNG aliases, rather than a JPEG-only handler. Browser proof signs and
reads all four endian/flavor combinations, checks the two nonadjacent exclusions,
detects pixel tampering, reads detached TIFF stores, and validates classic TIFF
output through the pinned legacy SDK. DNG tests prove aliases, not a real DNG
camera corpus or all DNG-specific metadata. Native Node tests ensure both read and
sign sessions actually select TIFF; the Neon addon suites preserve existing
JPEG behavior. Other-format remote pointers, extended XMP, fragmented BMFF, and
Worker/runtime parity remain open.

The next Worker-hosting slice is implemented as the explicit
`c2pa-js-state-machine/worker` entry, using an external module Worker and the same
async Wasm adapters as inline. Each runtime owns its Worker, Wasm realm, and
resource handles. A readiness handshake precedes URL/precompiled-module
initialization; startup errors or the 30-second initialization deadline terminate
the Worker. Signing/timestamp callbacks remain on the caller thread, while Blob
reads, hashing, and bounded remote/OCSP fetches run in the Worker. Abort signals
cross as messages; OCSP retains its existing inaccessible-response policy.
Reader/builder proxies expose the implemented inline method shapes, reject
freed handles, and do not enumerate/serialize their handles. Busy-builder free
defers Wasm cleanup; disposal terminates the Worker and rejects pending work.
Caller signing Promises cannot themselves be canceled, but late results are
ignored after disposal. Input buffers are cloned, not detached.

Three-browser proof covers separate URL/module instances, failed-loader retry,
trusted Worker/inline read-back, detached/concurrent reads, malformed input,
invalid handles, caller signing/timestamp failures, busy/free/disposal behavior,
real remote-fetch abort/retry, signed OCSP good/revoked/inaccessible outcomes,
and external module Workers under self-only CSP versus `worker-src 'none'`.
This is a supported-operation bridge, not complete upstream Worker parity.
Successful local Worker TSA interoperability is now proven with ephemeral
RSA/SHA-256 RFC 3161 responses generated for each actual request and independently
verified by OpenSSL. Three-browser cases cover concurrent callbacks and
definition URL precedence, `Trusted`/`timeStamp.validated` embedded read-back
through Worker, inline and pinned legacy, detached Worker/inline parity, explicit
missing-callback/refusal/malformed failures and same-builder retry. An authentic
wrong-imprint token reports informational `timeStamp.mismatch` and cannot supply
trusted time; the existing reader evaluates the signer using the host clock.
Public TSA/algorithm breadth and expired-signer longevity are not established.
No production transport or fallback is added.

Private tarball consumption now passes a separate packaging gate: emit ESM/types,
stage generated Wasm with fresh Rust provenance, pack only compiled files and the
manifest, and install offline into an isolated external consumer. TypeScript
resolves the installed exports; Vite 6.3.6 production output passes inline/Worker
URL and precompiled-Wasm loading, direct Worker-entry loading, sign/read
cross-validation, unchanged detached output, malformed rejection and cleanup in
all three browsers. The staged package has pinned runtime utilities and remains
private; no registry publication, source aliases or workspace links are used.
Packaging adds no upstream test passes. Source development and explicit backend
choice are preserved; no rollout/contraction occurs.

Supported reader-factory loader settings now work in inline and Worker hosts.
The shared legacy `mergeSettings` helper preserves deep field/array behavior;
per-read overrides retain unspecified defaults. Static Reader Contexts do not
inherit loader defaults, matching pinned legacy semantics. Three-browser
comparisons prove trust inheritance/clearing, static isolation and retries;
real signed OCSP proves an inherited enabled flag still requires a per-operation
authorized transport. Installed package consumers exercise defaults too.
New runtimes deliberately snapshot defaults rather than retaining the legacy
mutable configuration reference. Builder factories reject nonempty defaults
until builder settings are implemented; static builders remain independent.
Unsupported settings reject, and no global configuration grants network access.

Classic Workers, full settings/builder inheritance, registry publication and other bundlers, and
large-asset memory/event-loop measurements remain open.
Performance evidence now includes the new Worker path alongside
legacy Worker and inline, with within-Worker reads distinguished from
cross-thread messages; it does not isolate pure boundary cost.

The selected seventeen unchanged upstream reader declarations now run through both
inline and module Worker on all three browsers (102 runtime executions).
The `readerRuntimes` ledger gate checks exact runtime/browser/selected-ID coverage
and consistency with aggregate upstream outcomes. Failures on either path
prevent a passing upstream observation; no legacy fallback or rewritten
assertions are used. Unique upstream coverage is now 17/249, not 102/249.
The latest six additions cover omitted-format detection, explicit Contexts,
independent Contexts on one runtime, Context resolution reuse, deprecated
factory creation and per-call override precedence. These follow the original
disabled-trust/creation/trusted/untrusted store goldens, embedded-thumbnail
extraction and active-manifest equality. JSON differential cases are additional migration
tests, not new frozen upstream declarations.

The Worker now resolves the caller's Context before dispatch, using the same
`toJson()` contract as inline instead of creating a new Context for every read.
Typed transport carries resolved JSON plus settings for admission checks, and
the inline reader accepts the narrow settings/toJson interface for this bridge.
Repeated use shares the original Context's cached Promise/policy; new Contexts
are required for changed settings. Concurrent full-report comparisons against
legacy prove opposite trust policies stay isolated. Resolution failures and
disposal while resolving reject without dispatch; subsequent supported reads
work. The private Worker protocol moves to v2 so stale v1 scripts fail startup,
not silently re-resolve settings. Installed URL/module paths prove the same
memoized-policy and concurrent-isolation behavior. Client and Worker must ship
together; selecting legacy remains the explicit rollback.
Rust retains embedded binary assertion payloads, projects claim-thumbnail
references, and supplies copied bytes via `resourceToBytes` through Wasm and
both JS runtimes. Added tests prove exact legacy metadata/bytes, independent
copies, missing-identifier recovery, URI scope and free/dispose behavior.
The installed private-package proof also extracts the thumbnail on all paths.
No new asset reads, JavaScript decoding, implicit network fetch, or legacy
fallback is introduced. Resource payloads remain in the reader's memory and
their provenance still depends on validation results.

Generator icons now project legacy `{format, identifier}` references for exact
embedded assertion resources in the owning manifest. Relative and already
absolute same-owner URIs are supported; missing/ambiguous, cross-manifest,
external and deprecated databox references reject serialization rather than
disappearing or performing I/O. Real c2pa-rs-generated v2 fixtures match complete
trusted active/store/parsed-JSON reports and exact independent icon bytes on
inline and Worker. Tampering retains `assertion.hashedURI.mismatch`. A v1
databox fixture proves explicit rejection, cleanup and subsequent modern reads.
Installed URL/module consumers check trusted icon extraction and copy ownership,
and the actual Node addon proves the shared metadata projection (the later
resource slice below adds extraction). Identical icon references already in the assertion list are hashed
once, avoiding duplicate observations; conflicting hashes/algorithms still
validate separately. These three additional browser cases raise the bounded M3
gate to 171 executions, without changing 17/249 upstream coverage. No builder
icon-writing API, implicit fetch, fallback or default-backend change is added.

Ingredient thumbnails now share the generator-icon exact-owner resolver.
Supported v1/v2/v3 assertions project relative or same-owner absolute hashed
URIs into legacy `thumbnail` references; positional resource labels remain
distinct. Genuine c2pa-rs v2 claims match complete trusted active/store/parsed
JSON legacy reports and exact independent resource bytes on inline and Worker.
Tampering records live hash failures without modifying the second thumbnail.
Native tests cover malformed/missing/ambiguous/external/cross-owner references
and preserve linked-history guards. A real v1 databox fixture fails reporting
explicitly, remains releasable, and permits later modern reads. All installed
URL/module paths prove extraction and actual Node tests share both metadata
references (the later resource slice below adds Node extraction). This raises the bounded M3 gate to 180
executions without adding frozen upstream passes (still 17/249). Linked
histories/redactions, databoxes and resource writing remain
separate work; no implicit fetch, fallback or backend-default change is added.

Ingredient `data` now follows the same exact-owner embedded-resource path,
including positional labels and coexistence with a thumbnail. A genuine c2pa-rs
v2 fixture matches complete trusted legacy active/store/parsed-JSON reports and
exact independent bytes for both data resources on inline/Worker. Tampering one
payload preserves its live hash failure while leaving the other data/thumbnail
unchanged. Native tests preserve v1/v2/v3 shape/owner boundaries and linked-history
guards; a real v1 databox-data fixture rejects explicitly and later embedded
reads recover. Installed URL/module paths extract both kinds and Node shares
metadata reporting. This raises the bounded M3 gate to 189 executions, not the
17/249 frozen count. Full ingredient-link/hash/history/redaction validation,
databoxes and resource-writing APIs remain separate. No parsing/trusting of
extracted data, implicit fetch, fallback or backend promotion is added.

The Node resource gap is now closed for these embedded assertion resources.
`resourceToAsset` accepts legacy buffer/file destinations and returns
`{buffer, bytes_written}` (an empty buffer for file output). `sessionFinish`
retains an immutable private reader handle alongside JSON rather than discarding
the validated payloads. Browser and Node readers share one exact, unique
absolute-URI lookup; Rust performs no I/O or async work. JS owns asynchronous
file writes, and native handles/resources live until garbage collection.
Six actual-Node cases adapt the pinned upstream file-output test to the local
claim-thumbnail fixture, and cover generator icons, positional ingredient
thumbnails/data, exact copies, file shapes/truncation, source closure, no fetch,
tamper isolation, output/lookup failures and recovery. A native differential
test compares Node and the async browser host; shared tests reject ambiguous
resource and manifest owners. This adds feature proof, not frozen upstream
passes or browser cases: 17/249 and 189 M3 executions remain unchanged. Databoxes,
external resources and full Node API parity remain open. Large resource copies
are synchronous; this is not a new streaming or event-loop latency guarantee.

The next Node slice wires `fromManifestDataAndAsset` through that existing
session, extending `NodeSession::new` with optional detached store bytes rather
than adding a parallel native constructor. JS snapshots the supplied Buffer
before awaiting and retains source I/O/clock/OCSP ownership. Explicit bytes
never fall back or cause remote-manifest fetches; binding validation still uses
the supplied asset. `isEmbedded` distinguishes explicitly supplied stores, even
when the asset also has a valid embedded store; `remoteUrl` stays empty.

Six actual-Node cases adapt upstream detached buffer/file reads using a real
c2pa-rs store-free JPEG, sidecar and complete Trusted JSON golden (including named
trust provenance). They cover path/buffer/custom asynchronous sources, resource
bytes after source closure, concurrent trust isolation, pre-await manifest
snapshotting, malformed/unrelated sidecar precedence, tamper failures and recovery.
Native tests compare the browser async host, a conformance test rechecks the
fixture against real c2pa-rs, and the signing addon reads fresh output via the
new constructor. This is bounded Node JPEG detached/resource proof, not unchanged
upstream Node execution or full Context/settings/size-limit parity. Browser M3
counts and unique upstream passes remain unchanged; no default promotion,
automatic fallback or publication is added.

The ingredient manifest-link validation experiment was removed from this branch
on 2026-10-15 because it added domain behavior without unlocking a binding.
Its code, dedicated fixtures/tests and conformance-only reader dependency are
not part of the binding experiment. Ingredient-link/hash/history validation is
a future core dependency; linked-history compatibility reporting remains guarded.

The active-manifest slice preserves generator extensions and projects verified
claim/CAWG X.509 signer metadata (algorithm, subject organization/common name,
unsigned decimal serial, authenticated timestamp). `issuer` is legacy's subject
organization field. Reported unanchored timestamp times never become trusted
validation times. The identity compatibility field `revocation_status: true`
matches legacy's verified-credential report, not affirmative OCSP proof; actual
validation statuses retain their meaning. Internal hard-binding/resource
assertions remain available in the raw core report, not the compatibility list.
Native TIFF tests retain the exact nonadjacent-exclusion checks; browser tests
check binding success and pixel-tamper failure through the public report.
Three-browser comparisons cover complete active-manifest equality on both
runtimes and metadata stability with independent claim/identity anchors.
Object reporting surfaces use the same projection; `json()` applies legacy
display formatting separately.
Complete single-manifest trusted/untrusted reports now match legacy on both
runtimes. Top-level `validation_status` contains failures only and is omitted
when empty; success/informational observations remain in validation-result
buckets. Reporting preserves duplicate observations, scopes assertion URLs to
their actual manifest, orders legacy phases stably, and retains actual
claim/timestamp trust-list provenance separately from identity trust. Identity
credential distrust appears in the compatibility failure bucket without lowering
the engine's store validation state. Tampering remains visible alongside
unrelated successful checks. `verify.verifyTrust: false` now maps to an explicit
core claim-anchor policy, not adapter-side filtering; it cannot produce `Trusted`.
Signatures, presented certificate path/profile/validity, binding, timestamp and
revocation validation remain enabled. Boolean `trust`/`cawgTrust.verifyTrustList`
switches use the pinned utility's anchor omission semantics; CAWG distrust
remains visible. An otherwise trusted compatibility report with failure
observations is `Valid`, matching legacy without changing the engine report.
All four independent claim/CAWG combinations match complete object/JSON reports
against legacy on inline and Worker. Loader false defaults can be re-enabled
per read without leaking settings; installed packages retain signature
validation under false. Native tests retain expiration/profile/path-signature,
trusted timestamp and damaged-asset failures.
Linked-ingredient/history delta reports, broader resource references/external resources, `crJson`,
the dedicated upstream inline-entrypoint test,
and fragmented-asset declarations remain unported.
Parsed `json()` now matches legacy for the trusted and untrusted single-manifest
fixture on both runtimes. Like the pinned SDK, its display formatter converts
every nonempty all-number array stored as an object field to padded standard
base64, not only fields named `hash`. Empty/mixed arrays and direct nested arrays
remain arrays; unsigned integers contribute their low byte, while negative and
floating-point values are omitted. This deliberately lossy legacy view is not
used by `manifestStore()` or `activeManifest()`, and repeated JSON calls do not
mutate those objects. A newly signed custom assertion verifies these edge cases
against legacy in all browsers. Native JS/Node hosts share the formatter and
return serialization errors rather than `"{}"`; Wasm/Neon surface those errors.
Installed-package checks verify both byte-array and base64 identity-hash views.
This proves parsed JSON values, not whitespace/key-order byte equality or
`crJson`. Other certificate directory-string encodings remain open.

Resource-free v1/v2/v3 ingredients now project signed metadata to `ingredients`
in assertion order, retaining positional labels and version-specific field
names. The core emits owner-qualified `ingredient.unknownProvenance` for
`parentOf`/`componentOf` without a declared source manifest (`inputTo` is exempt).
The compatibility adapter groups these observations in `ingredientDeltas`;
they never suppress live signature/binding failures or represent validated
source assets. A newly signed four-ingredient asset's complete object/JSON
reports match legacy on both runtimes; ingredient tampering remains `Invalid`.
Installed packages and real Node addons exercise the shared projection.

Assertion `metadata` now projects creation-time text, review ratings and custom
extensions on all three versions. Complete legacy object/JSON comparisons cover
empty/null optionals, ignored unknown review fields, unsigned-byte rating
boundaries and custom metadata's array/base64 formatting. Review codes remain
asserted opinions, never active validation statuses; review tampering still
produces a live hashed-URI mismatch. Malformed ratings reject explicitly instead
of silently dropping the ingredient's metadata. Creation time is not trusted
validation time. Actual addons and private installed consumers check this path.

Linked-manifest/resource references, structured metadata (`reference`,
`dataSource`, `localizations`, `regionOfInterest`) and recorded validation
payloads fail compatibility serialization explicitly until their interpretation
and validation are implemented; unsupported versions and malformed supported
fields also error (stricter than legacy's optional-field dropping). Readers
remain releasable and subsequent supported reads succeed. No new frozen
upstream declaration is claimed for these migration-only differential cases:
these cases do not contribute to the current 17/249 count. Full ingredient link/hash validation,
historical-delta comparison, resources and builder ingredient APIs remain open.
The full-report differential also exposed a missing skipped-OCSP observation
when online checking is disabled and no signer check plan exists; the core now
reports that skip without new I/O or a successful-revocation claim.

Complete broader upstream Worker/inline parity and package exports beyond the now-proven
module/URL loading, external-Worker CSP, cleanup, and invalid-handle slice.
Add test-only host counters
and interleaving traces; run the unsigned-JPEG and signed-JPEG before/after
boundary-cost comparisons described above. Measure large-asset memory and
event-loop stalls against the pinned legacy backend. Record measurements before
choosing regression budgets; do not invent a performance threshold without a
baseline.

**Exit:** upstream reader/inline/serialization tests pass on both runtime paths,
and supported formats, resources, detached and remote manifests are accounted
for without legacy fallback.

### M4: builder and Node surface parity

Expand beyond baseline signing: default definitions and ID generation at the
host, JSON/CBOR assertions, actions and transformations, archives, ingredients,
redactions, resources, external/detached output, CAWG credential-holder callbacks,
and all pinned signer/identity/Trustmark interfaces.

Definition-editing callbacks must preserve metadata/order and be atomic on
exceptions. For Node keep upstream synchronous editing behavior; browser
methods retain their Promise/Worker semantics. Preserve atomic output replacement
and streaming in the existing Node/file-builder implementation. Once the
same signing cases are supported on both backends, add a matched signing
before/after measurement and include signer-boundary calls and awaits separately
from asset I/O.

**Exit:** complete web and Node builder suites pass unchanged against the new
backend, and outputs validate in both readers. Run the exact same application
sources against both compatibility entries, with TypeScript compilation as well
as runtime tests.

### M5: full parity and opt-in rollout

Require every ledger case to pass for its applicable platform, including
utilities/types/package contracts; every accepted deviation remains a blocker
to an unqualified full-parity claim. Test the distributed tarball, not only source
aliases. Add differential corpus runs and then track upstream changes as new
ledger entries before updating the pinned oracle.

Only then consider changing the default backend. No removal of legacy entry
points is part of this plan.

## Concrete upstream test mapping

Line numbers below identify original test starts at the pinned revision.
M1 uses a small explicit gate; all other cases remain required for full parity.

| Upstream source | Cases / behavior | Gate |
| --- | --- | --- |
| [Web reader][web-reader] | 54 unsigned/null; 64 asset limit; 302 errors; 408 free; 420 private fields | M1 |
| [Web reader][web-reader] | 40 complete report; 77 format sniffing with original report; 91/124/164 Context handling; 253 resource bytes; 280 active manifest; 313/339/362 complete trust goldens | M2 |
| [Web reader][web-reader] | 185/205 fragmented BMFF; 221/235 fragment limits; 385 remote manifest | M3 |
| [Web reader][web-reader] | 436/448/467 deprecated factories and settings precedence | M2/M3 |
| [Inline][inline] and [sanitization][sanitize] | inline smoke; nullish stores, null-prototype maps, `__proto__` labels and siblings | M3 |
| [Web builder][web-builder] | 29/133 definitions; 185/217/263 archive round trips; 336 actions; 373/411 redactions; 466+ ingredients | M4 |
| [Web builder][web-builder] | 577/615/684 filtering; 698/727/755/768/790 assertion edits; 841+ action transforms; 1206/1232 ingredient callbacks | M4 |
| [Web builder][web-builder] | 1250 JXL signing; 1286 CAWG signer payload; 1354 reservation failure/recovery; 1400+ factories/settings | M4 |
| [Node reader][node-reader] | 122/135 buffers; 145/155 files/sniffing; 167/174 unsigned/limit; 184/198/212/245 detached/context; 278 output; 296/305 embedded flag; 316 CAWG | M2-M4 |
| [Node builder][node-builder] and remaining SDK suites | assertions, ingredients, redactions, external signing, atomic transforms, signer/settings/identity/Trustmark contracts | M4/M5 |

Use upstream's complete expected objects and byte fixtures. Do not replace
them with snapshots generated by the new implementation.

## Comparison rules and proposed commands

For reads, compare the full public result, including absent fields, ordered
arrays, validation codes/URLs, errors, resources, and identity outcomes.
Only ignore JSON object key order. Freeze time/network inputs; do not broadly
strip validation failures, unknown fields, timestamps, or status explanations.

For signing, compare definition semantics and expected decoded results with
per-test, explicit handling of generated IDs and signatures. Never claim
byte-identical signed assets with randomized ECDSA. Both outputs must validate
their own hard binding and signature through both readers; preserve all caller
supplied metadata. Separate algorithm capability gaps from wrapper bugs.

The M0 commands now exist:

```sh
npm --prefix c2pa-js-state-machine run prepare:upstream
npm --prefix c2pa-js-state-machine run inventory:check
npm --prefix c2pa-js-state-machine run typecheck
npm --prefix c2pa-js-state-machine test
npm --prefix c2pa-js-state-machine run test:oracle
npm --prefix c2pa-js-state-machine run report:parity
# Intentionally fails while the new backend is unported.
npm --prefix c2pa-js-state-machine run check:parity
```

The following remain **PROPOSED M1+ scripts**, not current commands:

```sh
npm --prefix c2pa-js-state-machine run build:wasm
npm --prefix c2pa-js-state-machine run typecheck:compat
npm --prefix c2pa-js-state-machine run test:browser:m1
npm --prefix c2pa-js-state-machine run test:browser:parity
npm --prefix c2pa-js-state-machine run test:node:parity
npm --prefix c2pa-js-state-machine run test:package
```

The M1 script runs all mandatory cases on Chromium/Firefox/WebKit. The full
parity commands fail for an unported, missing, skipped, or failing required case;
the report includes the pinned revision and pass/fail/unported denominators.
Publish JUnit output, the ledger, structural diffs, browser traces on failure,
and build/fixture hashes in CI. Keep oracle and new-backend results distinct.

Add a separate browser-runtime CI job beside the existing Wasm compilation and
Node addon jobs. Install browser binaries there and serve fixtures locally.
Existing Cargo validation remains separate; browser runtime success does not
replace Wasm portability, lint, MSRV, or format/conformance checks.

## Rollout and rollback proof

1. Keep legacy packages usable while applications select the new compatibility
   entry for one tested workflow at a time.
2. Offer the new host-aware client independently; switching APIs and switching
   engines need not happen in the same application change.
3. Test mixed legacy/new clients in one process, with independent contexts,
   workers, resource loaders, and output destinations. Do not share live handles.
4. Rollback selects the legacy factory for newly created clients, using the
   legacy resources/settings. Explicitly dispose/drain old clients; do not try
   to serialize or resume an in-flight Wasm session on the other backend.
5. Preserve already-signed assets and archive interoperability. Rollback tests
   read new-produced assets with legacy and confirm that a failed sign leaves
   an existing output unchanged and does not repeat signer/network side effects.

M0 establishes the frozen contract and passing legacy oracle. Completion of
the next implementation milestone means M1 runs and passes against the actual
state-machine browser bindings; that execution is not claimed yet.

[upstream]: https://github.com/contentauth/c2pa-js/tree/3c642db3e566f20ede9442090d1d414f424bcea1
[test-fixtures]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/test/methods.ts
[web-reader]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/lib/reader.spec.ts
[web-builder]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/lib/builder.spec.ts
[inline]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/inline.spec.ts
[sanitize]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/lib/worker/sanitizeManifestStore.spec.ts
[node-reader]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-node/js-src/Reader.spec.ts
[node-builder]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-node/js-src/Builder.spec.ts
