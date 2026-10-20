# Experiment reports

Each new experiment gets a separate, descriptive Markdown report here. Record
the question, executable command, acceptance checks, runtime/build provenance,
measurements, limitations and decision. Link the report from this index rather
than appending another unrelated experiment to the historical findings file.

| Experiment | Question |
| --- | --- |
| [Node compatibility facade](2026-10-16-node-compat-facade.md) | Can the same supported c2pa-node client scenarios run over the Worker API, with bounded migration overhead? |
| [PR 47: Rust sharing versus JS copying](2026-10-16-pr47-boundary-copying.md) | Which copies does the Rust payload-sharing change remove, and what remains at Neon/Wasm/Worker boundaries? |
| [Node file-output signing: parity and memory](2026-10-16-node-file-output-memory.md) | Can bounded file output remove signing-buffer overhead, and how does it compare with the existing SDK's destination paths? |
| [Node file-path input: parity and memory](2026-10-16-node-file-path-memory.md) | Can Worker-owned disk reads avoid source copies, and how do both SDKs compare with bytes versus paths? |
| [Reference SDK refresh: c2pa-rs 0.91.3](2026-10-16-sdk-baseline-refresh.md) | Which rebuilt upstream SDK checkout is used for parity comparisons going forward? |
| [File/Blob input: latency and memory](2026-10-16-file-blob-memory.md) | Does slice-backed input improve memory behavior, and what does it cost? |
| [Shared-host read and lifecycle](2026-10-16-shared-host-read.md) | Can one JS driver produce identical reports and lifecycle behavior in Node and three browsers? |
| [Shared-host signing and callbacks](2026-10-16-shared-host-signing.md) | Can application-owned asynchronous keys drive the synchronous builder safely across Workers? |
| [Neutral session bridge ownership](2026-10-16-session-bridge-ownership.md) | Which abstractions belong to the reusable bridge rather than Node or browser bindings? |
| [SDK-to-SDK performance](2026-10-16-sdk-performance.md) | How do actual public read/sign calls compare with the existing SDKs? |
| [Binary versus JSON transport](2026-10-16-binary-transport.md) | How much browser build cost comes from JSON bulk-byte serialization? |
| [Action-validation parity](2026-10-16-validation-parity.md) | Why does the Rust reader accept an action that c2pa-rs rejects? |

Historical observations were migrated without rerunning experiments. Each
report distinguishes the original evidence from subsequent implementation
changes; shared limitations and related reports are linked where applicable.
