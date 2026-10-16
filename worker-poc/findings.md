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

The new Rust code is only synchronous Wasm boundaries over `NodeSession` and
`NodeBuildSession`. Despite their names, those existing wrappers are portable. This is stronger
sharing than merely putting two different read-to-completion implementations
behind similar public APIs: JavaScript drives the same request/reply contract.

## Naming and ownership finding

`NodeSession` is named after its first consumer, not a Node dependency. It
adapts the existing file-reader session to numeric request handles and
plain-data requests/replies, with compatibility settings and result semantics.
The Node-specific Neon calls and Worker setup live outside it; the same wrapper
is used by the browser Wasm boundary.

**Proposed follow-up:** call it `ReadSessionBridge`, owned alongside its request
vocabulary in `contentauth-c2pa-session-bridge`. Keep shared compatibility types
runtime-neutral and keep actual platform bindings separate. This is a proposed
rename/extraction, not an implemented change or a reason to move compatibility
policy into the generic engine. See the
[proposal and preservation checks](README.md#proposed-neutral-session-name).

The protocol could also serve non-JavaScript hosts, with language-specific
adapters for ABI conversion and ownership. That portability is an architectural
possibility, not a tested binding: current Rust types are not a universal ABI,
and c2pa-js compatibility conventions should not be required by other hosts.
See [reuse beyond JavaScript](README.md#reuse-beyond-javascript).

## Scope and baseline

Clean branch `ale/shared-worker-poc`, based on local `main` commit
`97fac9b`. Separate worktree: `state-machine-worker-poc`. No code from the large
migration experiment was applied.

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

## Local performance observations

Environment: macOS arm64, Node 24.18.0, Playwright 1.60.0 and its installed
Chromium/Firefox/WebKit builds. Each client is warmed before three measured
reads and three builds of the generated 64 MiB input. Test commands run
sequentially; this is not a controlled hardware benchmark.

Initial read-only run (2026-10-15):

| Environment | Median caller duration | Median Worker duration | Largest application timer gap | Minimum timer ticks per read |
| --- | --- | --- | --- | --- |
| Node / Neon | 53.54 ms | 33.58 ms | 8.72 ms | 31 |
| Chromium / Wasm | 235.20 ms | 207.60 ms | 20.30 ms | 58 |
| Firefox / Wasm | 1,624 ms | 1,594 ms | 14 ms | 324 |
| WebKit / Wasm | 270 ms | 258 ms | 11 ms | 37 |

Signing run (2026-10-16), including application-side WebCrypto:

| Environment | Median caller build duration | Median Worker build duration | Minimum application timer ticks per build |
| --- | --- | --- | --- |
| Node / Neon | 128.56 ms | 85.42 ms | 94 |
| Chromium / Wasm | 2,270.40 ms | 2,229.30 ms | 562 |
| Firefox / Wasm | 11,352 ms | 11,292 ms | 2,323 |
| WebKit / Wasm | 2,573 ms | 2,534 ms | 321 |

Application tasks progress while the Worker validates the asset. The shared
driver deliberately does not periodically yield; uninterrupted Worker
computation is compatible with this selected requirement.

These observations establish **no production timing threshold**, UI frame
guarantee or performance equivalence between native/Wasm engines. Firefox's
larger observed duration is not attributed to a root cause by this experiment.
Different browser engines, timer clamping, allocator/GC behavior and development
hardware affect the observations.

Caller timing includes a complete synchronous snapshot, structured cloning,
queueing, and result delivery. Worker timing includes session setup, parsing,
hashing and report serialization. Subtracting them does not isolate FFI
overhead. Build Worker time additionally includes output buffering, write
serialization and the round trip awaiting the application signer. Input is
synthetic JPEG framing plus a zero tail, not physical disk
throughput or representative image metadata.

Large browser builds are materially slower than reads in this proof. Unlike
the read path, the Wasm build boundary serializes complete output write chunks
as JSON numeric arrays, then JavaScript parses and copies them. This is a
concrete extra data path and a candidate bottleneck, not an isolated cause of
the measured gap. A controlled binary-versus-JSON boundary comparison is a
better next experiment than adding scheduling machinery.

Ignored raw results contain browser user agents, input/fixture fingerprints,
native/Wasm and shared-source SHA-256 hashes, and all individual samples.
Regenerating fixtures changes randomized ECDSA signatures; each run compares
all environments against the same generated asset.

### Validation commands

The final run built the actual bindings and regenerated fixtures, then ran the
Node and browser contracts sequentially. All 12 measured signing samples had
identical request accounting, and each result's source/binary fingerprints
matched the current files.

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

The synchronous Wasm bridge uses JSON for requests, including build write
payloads, and copies byte replies. Signing also buffers, copies and clones the
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

Compare binary versus JSON transport for Wasm build write payloads while
holding domain behavior and the shared host constant. Preserve the identical
contract, then measure elapsed time and peak memory before selecting a
production boundary. File/Blob-backed sources/outputs are a separate option
when whole-input/output buffering becomes a demonstrated workload constraint.
No core async conversion, custom scheduler or new signing domain feature is
needed to investigate either issue.
