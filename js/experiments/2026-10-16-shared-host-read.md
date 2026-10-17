# Shared-host read and lifecycle proof

Migrated from the combined findings dated 2026-10-16. Measurements and test
counts below describe the original run, not a new execution.

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
- An actual **SDK-to-SDK comparison**, in the [SDK report](2026-10-16-sdk-performance.md), is the relevant performance
  baseline. The binary proof is competitive with the existing browser SDK on
  this narrow workload, but is slower than the existing Node SDK on 64 MiB
  operations. The JSON-to-binary speedup is not a speedup over c2pa-js.

At the time of these measurements, the Wasm boundary wrapped `NodeSession` and
`NodeBuildSession`. Those historical names were portable despite their names.
The promoted package now uses `ReadSessionBridge` and `BuildSessionBridge` from
the runtime-neutral `contentauth-c2pa-session-bridge`; JavaScript still drives
the same request/reply contract.

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
[read contract](../test/contract.mjs), [signing contract](../test/signing.mjs),
[Node runner](../test/node.test.mjs) and
[browser runner](../test/browser.mjs).

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

## Ownership and limitations

The measured byte-array path snapshots and clones entire inputs. This is intentionally safe and
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

## Reproduction and related reports

From `js/`, follow the [build prerequisites](../README.md#run-the-proof), then run
`npm test` and `npm run test:browser`. These also exercise the
[signing contract](2026-10-16-shared-host-signing.md). The later
[File/Blob experiment](2026-10-16-file-blob-memory.md) extends the original
byte-array ownership scope; it does not retroactively change these measurements.

[All experiment reports](README.md)
