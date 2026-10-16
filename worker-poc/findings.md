# Proof findings — 2026-10-15

## Verdict

The proposed shared-host architecture works for an offline JPEG read workflow:

- **The same JS facade, command service, session loop and acceptance contract**
  run in Node and Chromium, Firefox and WebKit.
- Browser uses Wasm; Node uses the existing Neon addon inside a Node Worker.
- The existing Rust session validates the same signed assets to identical
  complete reports and identical request accounting in all four environments.
- No Rust domain logic, Tokio, worker pool or manual cooperative scheduling
  was added.

The new Rust code is only a synchronous Wasm boundary over `NodeSession`.
Despite its name, that existing session wrapper is portable. This is stronger
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

The proof covers read only. Existing baseline ES256 signing generates test
assets; it is not a shared signing implementation. That choice keeps the
experiment bounded while exercising real parsing, crypto, trust, hard binding
and host transport. No missing functionality was added to the state machine.

## Functional evidence

The final run passes two Node tests and the same 11 named contract checks in
each browser, with no skipped browser engines. See
[contract](test/contract.mjs), [Node runner](test/node.test.mjs) and
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

## Local performance observations

Environment: macOS arm64, Node 24.18.0, Playwright 1.60.0 and its installed
Chromium/Firefox/WebKit builds. Each client is warmed before three measured
reads of the same generated 64 MiB signed input. The final test commands run
sequentially; this is not a controlled hardware benchmark.

| Environment | Median caller duration | Median Worker duration | Largest application timer gap | Minimum timer ticks per read |
| --- | --- | --- | --- | --- |
| Node / Neon | 53.54 ms | 33.58 ms | 8.72 ms | 31 |
| Chromium / Wasm | 235.20 ms | 207.60 ms | 20.30 ms | 58 |
| Firefox / Wasm | 1,624 ms | 1,594 ms | 14 ms | 324 |
| WebKit / Wasm | 270 ms | 258 ms | 11 ms | 37 |

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
overhead. Input is synthetic JPEG framing plus a zero tail, not physical disk
throughput or representative image metadata.

Ignored raw results contain browser user agents, input/fixture fingerprints,
native/Wasm and shared-source SHA-256 hashes, and all individual samples.
Regenerating fixtures changes randomized ECDSA signatures; each run compares
all environments against the same generated asset.

## Ownership and limitations

The proof snapshots and clones entire inputs. This is intentionally safe and
easy to understand, but costs caller time and memory proportional to input.
Worker isolation does not remove that cost. No peak memory measurement or
streaming guarantee is claimed. Future file/Blob host adapters should be
selected against actual workload requirements, not added preemptively.

The synchronous Wasm bridge uses JSON for request metadata and copies byte
replies. Production optimization could change these mechanics without moving
C2PA logic into JavaScript.

Operations on a client are serialized. Worker control-message responsiveness
during computation, cooperative cancellation, progress and shared signing
callbacks remain separate, unproven extensions. Abrupt Worker termination is
adequate here because reads have no output files or network side effects.

The proof uses the main branch's existing JPEG-only session/settings/report
surface. It says nothing about full c2pa-js parity, future formats or domain
features, or distribution across all Node ABIs and bundlers.

## Next useful experiment, only if selected

Add one baseline signing operation to the same service, with a caller-owned
async signer callback routed by operation identity. Prove signature bytes,
failure propagation and read-back through both adapters. Reuse current core
signing capabilities; do not introduce identity/timestamp/domain work just to
expand this proof.
