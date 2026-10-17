# SDK-to-SDK performance comparison

Migrated from the combined findings dated 2026-10-16. Measurements and test
counts below describe the original run, not a new execution.

## Scope

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
bytes; the [benchmark adapter](../benchmarks/sdk-benchmark.mjs) performs that work in JS
and its time is included in the public sign duration. These are the existing
public signer contracts, not identical callback implementations.

No cold-start, package-size, throughput/concurrency, event-loop latency,
peak-memory, streaming, file/network or full-feature parity claim is established.
Six local samples cannot establish a production performance budget or explain
Firefox's absolute duration.

### Reproduction and evidence

After building this proof and generating its test credentials, run
`npm run benchmark:sdk` from `js/` with an already built sibling c2pa-js checkout.
See [prerequisites](../README.md#sdk-to-sdk-benchmark). The harness lives in
[shared benchmark/acceptance](../benchmarks/sdk-benchmark.mjs),
[Node runner](../benchmarks/sdk-node.mjs), [browser adapter](../benchmarks/sdk-web.mjs),
[Playwright runner](../benchmarks/sdk-browser.mjs), and [SDK preparation](../benchmarks/sdk-prepare.mjs).
It does not install dependencies, edit the SDK checkout or clear its build dirs.

Ignored `results/sdk-{node,chromium,firefox,webkit}.json` persist every sample,
validation outcomes, user agents/runtime, timestamp, existing SDK provenance,
and SHA-256 fingerprints of sources, bindings and benchmark inputs. Regenerating
assets changes randomized ECDSA signatures; all environments in one run share
the same generated read inputs. These raw files are local evidence, not checked-in
benchmark data.

[All experiment reports](README.md)
