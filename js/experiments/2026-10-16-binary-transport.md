# Binary versus JSON write-payload transport

Migrated from the combined findings dated 2026-10-16. Measurements and test
counts below describe the original run, not a new execution.

## Supporting transport experiment: binary versus JSON

The earlier prototype-only timings are superseded as the SDK performance
baseline by the [SDK comparison](2026-10-16-sdk-performance.md). They established that application tasks
continue while Workers operate, but not a frame-time or SDK-parity guarantee.
The controlled experiment below remains useful to explain the binding decision:
it compares two paths within the proof, **not** the proof against existing SDKs.

macOS arm64, Node 24.18.0 and Playwright 1.60.0, with the same fixture set,
Wasm build, shared host and caller-owned
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

## Reproduction

From `js/`, follow the [build prerequisites](../README.md#run-the-proof), then run
`npm test` and `npm run test:browser`. The browser runner exercises both transports
and the [paired boundary harness](../benchmarks/boundary.mjs).

[All experiment reports](README.md)
