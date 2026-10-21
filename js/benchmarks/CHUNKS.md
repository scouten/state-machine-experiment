# Chunk/boundary experiment

This is a compile-time **Node/Neon** experiment against `a4469a6`, independent
of subsequent source/lease/zero-copy experiments. Nothing changes the shipped
64 KiB reader/builder hash chunks, four-request hash window, or 1 MiB
file-builder copy chunks. There are no new library dependencies or API knobs.

## Run

From the repository root, with Node >=20, Cargo/Rust >=1.96, npm and tar:

```sh
npm --prefix js run bench:chunks
# Optional, harness-only sample count (default five):
CHUNK_SAMPLES=9 npm --prefix js run bench:chunks
```

The harness extracts **only committed `a4469a6`** into the ignored,
project-relative `js/results/chunks/source/`, builds both real release Neon
addons, and changes three guarded private constant declarations in that mirror.
It never edits production sources or another checkout. The mirror is replaced
on each invocation; Cargo's target cache beside it is reused. First builds may
resolve/download dependencies. Lockfile hashes record the actual resolution;
this is not a claim that the historical dependency graph was locked.
Do not run two sweeps concurrently in the same checkout.

It sweeps 16/64/256/1024 KiB hashing (reader **and** builder together) with
1 MiB source forwarding, then 64 KiB/4 MiB forwarding with baseline hashing.
The four-request window is unchanged. A final baseline measures order/drift.
Each native build runs in a fresh Node process, preventing module-cache reuse.
There is one unmeasured warmup and five measured samples per operation/size.
No thresholds or automatic production-policy selection are applied.

## Proof and measurement

The fixture is a four-byte JPEG and a 64 MiB + 17 byte JPEG-framed, zero-tailed
source, generated in memory using the existing public **test-only** ES256
credentials. Baseline signatures are captured once, then replayed only after
checking the signing-input SHA-256. All configurations must produce identical
whole-asset and manifest SHA-256, exclusions and complete `Trusted` reports at
the fixed verification time. Every measured build/read is checked outside its
timed interval. Every configuration/size also signs and validates through the
real Node Worker client outside timing. No large fixtures are checked in.
Fresh ECDSA signatures can change digests between independent sweeps; equality
is asserted across variants within a sweep, not against a historical signature.

The timed path runs the baseline's **unchanged shared JS drive and Node adapter**
in the same thread, not the client/Worker message transport. This isolates a
useful controlled chunk-to-Neon boundary path rather than mislabeling total
Worker latency as FFI time. Build timing includes real hashing, output assembly,
session work and a signature-replay callback, **not fresh private-key signing**.
Read timing includes actual certificate/signature/hash validation. Measurement
wrappers add counter overhead. No I/O/network/timestamp or realistic JPEG
metadata workloads are represented.
Advance and fulfill calls are counted; the fixed one create/finish per operation
is timed but not included in those counters.

`js/results/chunks/evidence.json` contains all raw elapsed samples, exact
request counters, provenance (OS/CPU/runtime, baseline SHA, policy/addon/harness
hashes, lock hashes), and output digests. `reference.json` contains the generated
baseline proof and replay signatures. These are ignored. Checked-in compact
results are in [chunks-evidence.json](chunks-evidence.json).

### Accounting, not allocator telemetry

`assetCopyBytes` and `assetAllocationEvents` are **selected source-visible
asset-path accounting proxies**, not measured heap allocations or all copies:

* Each byte reply allocates/copies a Rust `Vec` in the Neon `fulfill` boundary
  (`c2pa-node-{compat,sign}-addon/src/lib.rs`).
* Reader `Buffer.from(arrayBuffer, offset, length)` is a view. Builder
  `Buffer.from(Uint8Array)` allocates/copies once more
  (`js/src/node/adapter.mjs`).
* Each write allocates/copies a Neon `JsBuffer`; shared `drive.mjs` copies it
  into output. Its geometric growth allocates a new typed array and copies the
  **old capacity**, not just the logical length. The harness derives those
  growth events from actual write offsets/sizes using the unchanged formula.
* The final output slice copies its logical length; the event count includes
  this and the initial zero-length output typed-array construction.

Thus read selected copies = reply bytes; build selected copies =
`2 × reply bytes + 2 × write bytes + old capacities copied + final output bytes`.
Events = one per read reply; build events =
`2 × byte replies + write buffers + growths + 2`.
Counts exclude view objects, certificates, signer payloads/signatures, finish
manifest buffers, JSON/strings, internal Rust/session/hash copies, allocator
rounding, GC and message snapshots/clones. `growthAllocatedBytes` sums requested
output capacities; `maxReplyBytes` is the maximum *observed* reply (manifest
reads may exceed a hash chunk). Neither is a live-memory high-water mark.
Node may satisfy Buffer constructions from pooled backing slabs: the event
proxy counts construction/copy sites, not fresh allocator calls.

In particular, **summed copy volumes are not peak RSS**, fewer selected events
do not prove lower peak memory, and this does not establish physical browser
zero-copy. Browser Wasm uses the same host protocol but a different adapter,
linear-memory allocation/copying and runtime; it was **not measured here**.

## Representative results

Apple M2 Max / macOS arm64, Node 22.22.0, Rust 1.98.1, release addons:
all seven builds passed, with 140 measured operations, 28 warmups, plus setup
and 14 real Worker sign/read roundtrips. Tiny source counters were invariant.
For the 64 MiB + 17 byte source:

| Hash / source-copy KiB | Read advance / fulfill | Build advance / fulfill | Read / build selected allocation events | Build selected copy bytes |
|---|---:|---:|---:|---:|
| 64 / 1024 (baseline) | 137 / 1033 | 270 / 1166 | 1030 / 2267 | 535,947,433 |
| 16 / 1024 | 521 / 4105 | 654 / 4238 | 4102 / 8411 | 535,947,433 |
| 256 / 1024 | 41 / 265 | 174 / 398 | 262 / 731 | 535,947,433 |
| 1024 / 1024 | 17 / 73 | 150 / 206 | 70 / 347 | 535,947,433 |
| 64 / 64 | 137 / 1033 | 2190 / 3086 | 1030 / 5151 | 538,637,353 |
| 64 / 4096 | 137 / 1033 | 174 / 1070 | 1030 / 2121 | 532,716,361 |

Increasing hash chunks from 64 KiB to 1 MiB reduced read byte replies from
1030 to 70 (93.2%) and selected build allocation events from 2267 to 347
(84.7%), **without reducing selected copied bytes**. Read selected copies
remained 67,110,663 bytes. Larger source chunks reduced writes/growth events
but only slightly reduced selected copy volume (1 MiB to 4 MiB: about 0.6%).
These are mechanism counts, not evidence for pooling or a production default.

Elapsed samples were unstable on the shared machine: unchanged baseline
read/build medians were **119.545 / 245.444 ms** initially versus
**37.335 / 74.247 ms** at the end. The checked-in evidence retains all large
elapsed samples, including outliers. **Do not rank chunk sizes by these
timings or attribute the apparent differences to boundary costs.**

## Stop condition / next trigger

The experiment stops at byte/report-preserving measurements. Do not add
production chunk knobs or pooling from this sweep alone. Before choosing a
policy, repeat on representative assets, other hardware, interleaved runs and
the actual browser Wasm boundary; separately profile allocator/peak memory.
Larger chunks also enlarge the outstanding hash window in bytes. This harness
does not prove a globally optimal chunk size or an SDK-wide speedup.
