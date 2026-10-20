# Proof findings — 2026-10-16

## Verdict

The proposed shared-host architecture works for offline JPEG reading and
baseline ES256 signing:

- **The same JS facade, command service, session loop and acceptance contract**
  run in Node and Chromium, Firefox and WebKit.
- Browser uses Wasm; Node uses the existing Neon addons inside a Node Worker.
- The existing Rust reader session validates the same signed assets to identical
  complete reports and identical request accounting in all four environments.
- The existing builder session generates signed assets with a caller-owned
  asynchronous WebCrypto signer outside the Worker. Results read back `Trusted`
  and match the existing direct signing host's complete validation reports.
- No Rust domain logic, Tokio, worker pool or manual cooperative scheduling
  was added.
- A paired same-binary experiment identifies JSON write-payload transport as a
  major avoidable browser signing cost. Binary payloads preserve the contracts
  and reduce median large-build caller duration by about 6.7–8.5 times.
- An actual **SDK-to-SDK comparison**, below, is the relevant performance
  baseline. The binary proof is competitive with the existing browser SDK on
  this narrow workload, but is slower than the existing Node SDK on 64 MiB
  operations. The JSON-to-binary speedup is not a speedup over c2pa-js.

At the time of these measurements, the Wasm boundary wrapped `NodeSession` and
`NodeBuildSession`. Those historical names were portable despite their names.
The promoted package now uses `ReadSessionBridge` and `BuildSessionBridge` from
the runtime-neutral `contentauth-c2pa-session-bridge`; JavaScript still drives
the same request/reply contract.

## Naming and ownership finding

`NodeSession` was named after its first consumer, not a Node dependency. Its
request-handle and plain-data contract is now owned by `ReadSessionBridge` in
`contentauth-c2pa-session-bridge`; `BuildSessionBridge` owns the signing
vocabulary and report. Shared compatibility context, manifest-store and error
types live beside both bridges. Neon and Wasm are consumers, not owners. See
[current bridge ownership](README.md#neutral-session-bridge).

The protocol could also serve non-JavaScript hosts, with language-specific
adapters for ABI conversion and ownership. That portability is an architectural
possibility, not a tested binding: current Rust types are not a universal ABI,
and c2pa-js compatibility conventions should not be required by other hosts.
See [reuse beyond JavaScript](README.md#reuse-beyond-javascript).

## Scope and baseline

The measurements were produced on branch `ale/shared-worker-poc`, based on
local `main` commit `97fac9b`. No code from the large migration experiment was
applied.

The proof covers reading and the existing baseline signing case: one
`c2pa.created` assertion, JPEG, ES256, no timestamp or identity. The direct
signing host generates fixtures and records reference COSE inputs, algorithms,
reports and exclusions. The Worker signing contract uses those same inputs,
but signs with an application-held non-extractable WebCrypto key. No missing
functionality was added to the state machine.

## Functional evidence

The final run passes four Node tests and the same 11 read and 13 signing contract
checks in each browser, with no skipped browser engines. See
[read contract](test/contract.mjs), [signing contract](test/signing.mjs),
[Node runner](test/node.test.mjs) and
[browser runner](test/browser.mjs).

Small and 64 MiB signed inputs are read `Trusted`. Complete reports match the
existing direct native Node host, including:

- `claimSignature.validated`
- `claimSignature.insideValidity`
- `signingCredential.trusted`
- `assertion.dataHash.match`

The large input produces **1,029 reads, 67,110,652 requested bytes, a 65,536-byte
maximum read and 137 advances** in every environment. Last-byte tampering
produces `Invalid`; unsigned JPEG produces `null`. Invalid settings/malformed
assets reject, and later operations still succeed.

Caller mutation after invocation does not affect the read and caller storage
is not detached. Queued operations return their own reports. Disposing one
client rejects its pending operation without breaking a second client.
Startup/crash error propagation is checked with a controlled port failure;
native crashes and graceful cancellation are not tested or promised.

### Signing and callback findings

- Small and 64 MiB unsigned JPEGs are signed and read back `Trusted`. Algorithms
  and exact COSE signing input bytes match the direct host. Complete read-back
  reports, output/manifest lengths and separate exclusion ranges match too;
  randomized ECDSA signatures need not be byte-identical.
- One large build issues **1,092 reads, 134,217,734 read bytes, 68 writes,
  67,112,416 written bytes, one signature and 268 advances** in all four
  environments. Input is 67,108,864 bytes; output is 67,110,646 bytes.
  Read/write totals include output hashing and placeholder/commit rewrites,
  not just unique source/output bytes.
- The key and callback function never cross the Worker boundary. The same
  application-side WebCrypto signer works unchanged in Node and browsers.
  Snapshot tests cover source bytes, definition and public certificate bytes.
- Delayed signatures leave the build pending while application timer tasks
  progress. Callback replies must bypass the serialized top-level queue:
  otherwise a reply would wait behind the very build awaiting it.
- Replies carry both operation identity and Rust request handle. Queued small
  and large builds mixed with a read return the correct reports; another
  Worker finishes a different build while the first callback remains pending.
- Synchronous throws and async rejections preserve error name/message. Invalid
  reply types/lengths and invalid definitions reject; subsequent builds succeed.
  Original error identity and stack do not survive serialization.
- A 64-byte zero signature passes the transport shape check but reads back
  `Invalid`. Successful building is not signature verification or a trust
  verdict; this remains the signer's responsibility followed by validation.
- Disposal rejects a build without waiting for its signer. Late signature
  success and rejection do not post to the terminated Worker or affect another
  client. The caller-owned signing operation itself is not cancelled.
- Controlled port tests also prove callback transport failures close the client
  and reject its pending operations. Browser harnesses fail on unhandled page
  errors rather than merely logging them.

## SDK-to-SDK performance comparison

This is a comparison of **real public SDK calls**, not a direct Rust host versus
the same implementation in a Worker. Both libraries actually run their Rust
validation/signing engines. The proof uses its current binary browser transport;
the existing SDKs already use byte-oriented transport, not the proof's old JSON
numeric-array path.

### What was compared

- Existing `@contentauth/c2pa-node` **0.9.9** and `@contentauth/c2pa-web`
  **0.15.3**, from the sibling c2pa-js checkout at
  `3c642db3e566f20ede9442090d1d414f424bcea1`. Its Cargo lock resolves c2pa-rs
  **0.91.0**. Node uses the existing built Neon addon and async public API;
  browser uses the actual public facade and its default inline Worker.
- The shared Worker proof on `ale/shared-worker-poc`, including the binary Wasm
  write boundary. Node uses its existing Neon addons inside a Worker; browsers
  use the synchronous Wasm session bridges inside a Worker.
- macOS arm64, Node **24.18.0**, Playwright **1.60.0**, headless Chromium,
  Firefox and WebKit. Runs are sequential on local development hardware, not
  isolated or representative of every user's device.

**Build provenance limitation:** the existing web facade/inline Worker was
bundled from checkout source using its installed Vite; its Wasm binary and the
Node distribution were pre-existing builds, not rebuilt or obtained as freshly
installed published releases. Their hashes and the checkout/lockfile are
recorded. The lock version does not independently establish which source
produced those binaries. This is a reproducible local-build comparison, not a
release certification.

### Workload and acceptance

The same unsigned JPEG, definition, key and trust certificate are used by both
SDKs. The small source is the existing SDK's unsigned test thumbnail
(**61,720 bytes**); the large source is that same JPEG padded with zeros after
EOI to **67,108,864 bytes**. Read inputs are the same proof-signed assets
(**63,583** and **67,110,727 bytes**). Padding forces hashing/copying of 64 MiB;
it is not a realistic large photograph or image-decoding benchmark.

The benchmark uses a shared `urn:c2pa:` label and adds the required
`digitalSourceType` to the `c2pa.created` action. This is intentionally different
from the earlier architecture fixtures: the existing SDK rejected their
four-byte unsigned JPEG at signing, and rejected their missing action field
as `assertion.action.malformed` on validation. The proof's validator accepted
that action. **That is a concrete validation-depth gap**, not merely a transport
issue; no Rust domain change was made to hide it.

Offline trust validation is enabled with the same test certificate. OCSP and
remote-manifest fetching are disabled; both use the current clock. Existing
SDK post-sign verification is explicitly disabled to match the proof, which
does not verify within `sign`. After every build, **both readers**, outside the
timed interval, must report `Trusted`, the expected title/action and signature,
credential-trust and data-hash successes. Both also reject last-byte tampering
with `Invalid` and `assertion.dataHash.mismatch` at each size.

Two warmups per SDK/size/operation precede **six measured alternating-order
pairs**. Each environment therefore records 48 operations: two SDKs, two sizes,
two operations and six samples. There are **192 measured operations** overall,
plus warmups and cross-validation. Signers must be called exactly once.

Read timing includes reader creation, validation and full JSON report retrieval;
sign timing includes new builder/signer setup, signing, embedding, and delivery
of the asset and manifest bytes. Awaited WebCrypto callbacks are included.
Fixture fetches, key import, trust-context creation, module/Worker startup and
browser Blob preparation are excluded. Explicit browser reader/builder frees
and cross-validation are outside the interval. Node readers/builders have no
explicit free API; GC and allocator effects are not controlled.

This measures each SDK's native public input contract: prebuilt Blob for the
existing browser SDK, Uint8Array for the proof and Buffer for existing Node.
The proof's synchronous snapshot, Worker clones and output copies are included;
the existing browser SDK's own byte transfers are included. These are real
ownership/API differences, not an isolated measurement of state-machine or
FFI overhead. Rust functionality, report detail and output policies also differ.

### Results

Warm caller duration in milliseconds, **median [minimum–maximum]**, six samples
per cell. Small numbers, especially browser results, are timer-resolution
sensitive. Ratios are not statistically established performance guarantees.

**Small source (61,720 bytes):**

| Environment | Operation | Existing SDK | State-machine proof |
| --- | --- | --- | --- |
| Node / Neon | Read | 0.79 [0.77–0.81] | 0.45 [0.43–0.46] |
| Node / Neon | Sign | 14.03 [13.82–14.52] | 0.42 [0.38–0.47] |
| Chromium / Wasm | Read | 2.65 [2.40–2.90] | 1.40 [1.40–1.60] |
| Chromium / Wasm | Sign | 2.95 [2.20–3.10] | 0.90 [0.70–0.90] |
| Firefox / Wasm | Read | 24 [23–25] | 11.50 [11–13] |
| Firefox / Wasm | Sign | 5.50 [4–8] | 3 [3–4] |
| WebKit / Wasm | Read | 4 [3–6] | 2 [2–4] |
| WebKit / Wasm | Sign | 4.50 [4–6] | 1.50 [1–2] |

**Large source (64 MiB):**

| Environment | Operation | Existing SDK | State-machine proof |
| --- | --- | --- | --- |
| Node / Neon | Read | 37.18 [34.06–40.87] | 45.87 [37.50–54.24] |
| Node / Neon | Sign | 66.84 [60.54–73.34] | 92.79 [87.89–98.38] |
| Chromium / Wasm | Read | 258.15 [256.90–273] | 219.60 [217.70–223.80] |
| Chromium / Wasm | Sign | 279.20 [278.70–283.10] | 265.95 [257.70–269.90] |
| Firefox / Wasm | Read | 1,726.50 [1,723–1,736] | 1,587 [1,581–1,594] |
| Firefox / Wasm | Sign | 1,724 [1,718–1,750] | 1,636 [1,624–1,669] |
| WebKit / Wasm | Read | 398 [383–407] | 266 [258–283] |
| WebKit / Wasm | Sign | 415 [407–423] | 304 [289–322] |

**Practical reading:** on 64 MiB operations, the proof's Node median is about
**23% slower reading and 39% slower signing**. In Chromium and Firefox,
large-build medians are close (about 5% lower in the proof); read medians are
about 15% and 8% lower respectively. WebKit has a larger observed reduction:
about 33% reading and 27% signing. The proof's small-operation medians are
lower in every environment, but the unequal fixed work below is especially
important there. This does not justify a general "faster SDK" claim.

### Interpretation and unequal work

These measurements do **not** show the proof is a drop-in, equally validating
replacement. The existing SDK implements much broader C2PA behavior and richer
reporting; the malformed-action finding above directly demonstrates this.
Conversely, the proof pays explicit whole-input snapshot and Worker-clone costs.
The experiment does not attribute differences to a particular layer.

Sign output is not byte-identical or identically sized. The proof emits a
**1,851-byte** manifest, existing web emits **11,160 bytes**, and existing Node
emits **60,708 bytes**, with their respective defaults/reservations. Small output
assets are **63,583 / 72,892 / 122,440 bytes** (proof / web / Node); large output
assets are **67,110,727 / 67,120,036 / 67,169,584 bytes**. Both validators accept
every output, but padding, generator metadata and policy are not normalized.
Node's much larger fixed manifest and small-sign latency are observations,
not proof that padding alone causes its timing.

The same caller-held non-extractable WebCrypto ES256 key is used throughout.
Existing Node and the proof request a raw ECDSA signature. Existing web instead
requires the callback to construct a complete padded COSE_Sign1 from claim
bytes; the [benchmark adapter](benchmarks/sdk-benchmark.mjs) performs that work in JS
and its time is included in the public sign duration. These are the existing
public signer contracts, not identical callback implementations.

No cold-start, package-size, throughput/concurrency, event-loop latency,
peak-memory, streaming, file/network or full-feature parity claim is established.
Six local samples cannot establish a production performance budget or explain
Firefox's absolute duration.

### Reproduction and evidence

After building this proof and generating its test credentials, run
`npm run benchmark:sdk` here with an already built sibling c2pa-js checkout.
See [prerequisites](README.md#sdk-to-sdk-benchmark). The harness lives in
[shared benchmark/acceptance](benchmarks/sdk-benchmark.mjs),
[Node runner](benchmarks/sdk-node.mjs), [browser adapter](benchmarks/sdk-web.mjs),
[Playwright runner](benchmarks/sdk-browser.mjs), and [SDK preparation](benchmarks/sdk-prepare.mjs).
It does not install dependencies, edit the SDK checkout or clear its build dirs.

Ignored `results/sdk-{node,chromium,firefox,webkit}.json` persist every sample,
validation outcomes, user agents/runtime, timestamp, existing SDK provenance,
and SHA-256 fingerprints of sources, bindings and benchmark inputs. Regenerating
assets changes randomized ECDSA signatures; all environments in one run share
the same generated read inputs. These raw files are local evidence, not checked-in
benchmark data.

## Supporting transport experiment: binary versus JSON

The earlier prototype-only timings are superseded as the SDK performance
baseline by the comparison above. They established that application tasks
continue while Workers operate, but not a frame-time or SDK-parity guarantee.
The controlled experiment below remains useful to explain the binding decision:
it compares two paths within the proof, **not** the proof against existing SDKs.

Same local environment, fixture set, Wasm build, shared host and caller-owned
WebCrypto signer. Two Worker clients differ only in the build boundary's write
payload representation. Both are warmed for small and large inputs, then four
pairs per size alternate JSON-first and binary-first. Each measured build is
validated outside its timing interval. Both also pass all 11 read and 13
signing checks unchanged in Chromium, Firefox and WebKit.

Median caller build duration:

| Browser | Small JSON | Small binary | 64 MiB JSON | 64 MiB binary | Large speedup |
| --- | --- | --- | --- | --- | --- |
| Chromium | 0.80 ms | 0.60 ms | 2,224.25 ms | 277.90 ms | 8.00x |
| Firefox | 2.50 ms | 2 ms | 11,368 ms | 1,697.50 ms | 6.70x |
| WebKit | 2 ms | 2 ms | 2,555.50 ms | 300 ms | 8.52x |

Median large-build boundary measurements, shown as JSON / binary:

| Browser | Worker duration | Wasm advance + serialization/string transfer | JS JSON parsing | Payload conversion/copy + normalization |
| --- | --- | --- | --- | --- |
| Chromium | 2,192.15 / 244.45 ms | 1,851.40 / 200.50 ms | 257.80 / 0.35 ms | 44.45 / 7 ms |
| Firefox | 11,315 / 1,651.50 ms | 10,367.50 / 1,598.50 ms | 809.50 / 1.50 ms | 81 / 5.50 ms |
| WebKit | 2,529.50 / 283.50 ms | 1,884.50 / 255.50 ms | 602.50 / 0.50 ms | 12 / 3.50 ms |

Every large build still writes 67,112,416 payload bytes in 68 requests.
JSON metadata/string volume falls from approximately **134.32 million
characters to 94,507**. The synthetic zero tail makes JSON payloads relatively
compact; other byte distributions are not measured. Signature randomness can
slightly vary JSON character counts, not output length or request accounting.

**Decision:** retain binary write payloads as the browser default. The original
JSON path is an explicit experiment control, not a production feature. No Rust
builder, shared JS driver, Neon adapter or signer policy changed.

These measurements identify a large avoidable transport cost. They do not
separately time Rust serialization versus string copying: `wasmAdvanceMs`
includes core work and both. The binary extraction still copies bytes; no
zero-copy or peak-memory improvement is established. Timing instrumentation is
identical in both paths; sub-millisecond/zero readings reflect timer resolution,
especially for tiny inputs. Four local pairs are not a production performance
budget or an explanation for remaining Firefox/native differences.

Node's unchanged native contracts also pass. Its results are a regression
reference, not a participant in the paired browser speedup calculation.

### Validation commands

The initial signing run built the actual bindings and regenerated fixtures,
then ran the Node and browser contracts sequentially. Its 12 measured signing
samples had identical request accounting. The boundary follow-up rebuilt Wasm,
kept the same fixtures, ran Node's 4/4 tests and both browser contracts, and
validated 48 additional paired builds (24 small, 24 large). Current result
artifacts include source/binary fingerprints.

Additional passing checks:

- Existing reader addon tests: 27/27.
- Existing signing addon tests: 26/26.
- Standalone Wasm `cargo clippy --target wasm32-unknown-unknown -- -Dwarnings`.
- Pinned nightly formatting check and Wasm rustdoc with warnings denied.
- JavaScript syntax and diff whitespace checks.

## Ownership and limitations

The proof snapshots and clones entire inputs. This is intentionally safe and
easy to understand, but costs caller time and memory proportional to input.
Worker isolation does not remove that cost. No peak memory measurement or
streaming guarantee is claimed. Future file/Blob host adapters should be
selected against actual workload requirements, not added preemptively.

The synchronous Wasm bridge uses JSON for metadata and binary bulk build write
payloads by default, and copies byte replies. Signing also buffers, copies and clones the
complete output asset back to the application. No output streaming or memory
budget is proven.

Operations on a client are serialized. Worker control-message responsiveness
during computation, cooperative cancellation and progress remain unproven.
The Worker performs no external writes or network operations; abrupt termination
discards its in-memory output. It does not cancel a remote/HSM signer or undo
any caller-owned side effects. A never-settling signer stalls its client's queue
until disposal; signer timeouts remain caller policy. A callback must not await
a queued operation on its own client; use an independent client instead.

The proof uses the main branch's existing JPEG-only session/settings/report
surface. It says nothing about full c2pa-js parity, future formats or domain
features, or distribution across all Node ABIs and bundlers.

## Next useful experiment, only if selected

Measure peak memory and copying across input sizes before choosing file/Blob-
backed sources and outputs. Binary payloads fix a demonstrated serialization
cost but do not remove whole-input/output buffering, extra copies or retained
Wasm memory. No core async conversion, custom scheduler or new signing domain
feature is needed to investigate those limits.
