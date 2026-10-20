# Node compatibility facade over the shared Worker host

## Summary

**A narrow c2pa-node-shaped migration surface works without changing Rust.**
The same supported client scenarios run against c2pa-node 0.9.10 and an opt-in
namespace backed by the existing shared Worker client.

The facade preserves Buffer/file input and output shapes, asynchronous signing
callbacks, unsigned `null` and report accessors. It does not emulate missing
Rust validation/reporting features, add formats, or claim full legacy API
compatibility. Unsupported options reject explicitly.

The facade retains the file-output memory benefit. At 64 MiB, median file
signing peak RSS was **158.1 MiB** through the facade, **157.5 MiB** through
the raw Worker API and **332.5 MiB** through the reference SDK in this run.
Three samples do not resolve small timing differences or establish a stable
per-call overhead.

## Ownership and public slice

[compat.mjs](../src/node/compat.mjs) creates a namespace bound to **one reused
Worker**, with explicit disposal:

```js
import { createNodeCompat } from "../src/node/compat.mjs";
const sdk = createNodeCompat();
const { Reader, Builder, CallbackSigner, Context } = sdk;
try {
  const context = new Context({
    trust: { userAnchors: inlinePem },
    verify: { ocspFetch: false, remoteManifestFetch: false,
      verifyAfterReading: true, verifyTrust: true, verifyAfterSign: false },
  });
  const reader = await Reader.fromAsset({ path: "signed.jpg" }, context);
  const report = reader?.json();
  const builder = await Builder.withJsonAsync(definition, context);
  const signer = CallbackSigner.newSigner({
    alg: "es256", certs: [pemCertificateBuffer],
    reserveSize: 10000, directCoseHandling: false,
  }, async (data) => signRawEs256(data));
  const destination = { buffer: null }; // Or { path: "output.jpg" }.
  const manifest = await builder.signAsync(signer, { path: "source.jpg" }, destination);
} finally {
  await sdk.dispose();
}
```

The scenario body can use the same class/method names against the reference
namespace. Migration changes the import/setup and adds explicit
`try/finally` disposal; it is not a zero-edit package replacement.

| Surface | Implemented slice |
| --- | --- |
| `Context` | Snapshotted raw settings object; inline PEM `trust.userAnchors`; supported offline switches |
| `Reader.fromAsset` | `{ buffer: Buffer, mimeType? }` or `{ path, mimeType? }`; JPEG only |
| `Reader` accessors | `json`, `activeLabel`, `getActive`; fresh snapshots on report access |
| Missing manifest | Resolves to `null` |
| `Builder.withJsonAsync` | Snapshotted existing baseline definition; no new domain conversion |
| `CallbackSigner.newSigner` | ES256, PEM Buffer certificates, raw-signature callback |
| Callback | Buffer input; returns 64 raw `r || s` bytes; key stays in application realm |
| `Builder.signAsync` | Buffer/file source; Buffer/file destination; returns manifest Buffer |
| Buffer destination | Assigns `destination.buffer` only on success; manifest/output use Buffer views over returned storage |
| File destination | Delegates to existing bounded file-output host; no asset return |
| Lifecycle | Serialized shared Worker queue; explicit namespace `dispose`, not native-handle API |

Settings conversion maps inline camel-case `userAnchors` to the existing
bridge's `user_anchors`. No new trust implementation. Accepted verify values
are `ocspFetch=false`, `remoteManifestFetch=false`, `verifyAfterReading=true`,
`verifyTrust=true`, `verifyAfterSign=false`. Omission uses the facade's offline
slice; this is not an assertion that all reference defaults are equivalent.

Only the measured signer configuration (`reserveSize=10000`,
`directCoseHandling=false`) is supported. `reserveSize` is exposed as a signer
configuration value, **not an implementation of variable Rust reservation**.
The actual manifest reservation/output remains controlled by the fixed Rust
builder. Other settings, algorithms, timestamps and direct-COSE mode fail
explicitly rather than being silently discarded.

The new file imports the shared client; it does not import the old addon
JavaScript drivers or duplicate their session loops. No Rust source, Cargo
manifest, native ABI, algorithm or feature capability was changed for this
experiment. Earlier uncommitted Rust characterization work in this worktree
is unrelated and was not modified here.

## Adapted upstream scenarios

Source baseline: c2pa-js commit
`20531aa26a219fee35937d3a51a77ebf7a0c03ef`:

- [`Reader.spec.ts`](https://github.com/contentauth/c2pa-js/blob/20531aa26a219fee35937d3a51a77ebf7a0c03ef/packages/c2pa-node/js-src/Reader.spec.ts):
  Buffer/path reads, omitted MIME, extensionless read and unsigned `null`;
  accessor consistency and report equality across source representations.
- [`Builder.spec.ts`](https://github.com/contentauth/c2pa-js/blob/20531aa26a219fee35937d3a51a77ebf7a0c03ef/packages/c2pa-node/js-src/Builder.spec.ts):
  callback signing into Buffer/file destinations and read-back.

These are newly authored adaptations in
[compat.test.mjs](../test/compat.test.mjs), not a claim to run those complete
upstream suites unchanged. We substitute the already-supported baseline
definition/certificates so ingredients, resources and other Rust capabilities
do not become part of this experiment.

The shared `clientScenarios` function changes only the namespace argument:
`existing` or `createNodeCompat()`. It tests:

- Complete report equality across path/Buffer/JPEG aliases **within each SDK**.
- `json/activeLabel/getActive` consistency and mutation isolation.
- Unsigned `null`, missing path/malformed source rejection, tamper `Invalid`.
- Both source shapes crossed with both destination shapes; manifest and
  destination Buffer types, signer callback Buffer type and exactly one call.
- Definition snapshot at construction and positive metadata preservation.
- Signer failure rejects without populating a destination Buffer; subsequent
  reads remain usable.
- All eight scenario-produced assets are independently Trusted by **both**
  SDKs.

Additional facade-specific checks cover rejection of unsupported configuration,
the Worker queue, mixed successful calls, callback error name/message retention,
disposal during a gated signer, queued rejection and temporary-file cleanup.
One explicit test compares the facade's complete report with the raw Worker
report, preventing the shim from filling Rust-origin gaps with invented data.

### Findings at the binding boundary

1. **Buffer identity/type needs deliberate adaptation.** Worker results arrive
   as Uint8Array; the facade returns Buffer views without another bulk copy.
2. **Signatures stay application-owned.** The facade converts public PEM
   certificates to DER for the existing bridge; it never receives private keys.
3. **Reference declaration and runtime differ.** In this reference build,
   `CallbackSigner.certs()` returns a flat number array containing PEM bytes,
   despite its Buffer-array type declaration. The tested single-chain facade
   getter matches the observed runtime shape. This is not a recommendation
   to depend on the discrepancy.
4. **Extensionless read and sign differ upstream.** An extensionless JPEG read
   is detected from bytes. Reference signing that same path needs explicit
   MIME; the shared signing scenarios therefore supply `image/jpeg`.
5. **Lifecycle cannot be hidden honestly.** A namespace owns a Worker; its
   explicit disposal is a migration requirement. Native reference objects have
   GC-finalized handles, not the same cancellation contract.

## Reproduction and evidence

Build both native SDKs and prepare the existing generated fixture/benchmark
metadata, as in the [file-output experiment](2026-10-16-node-file-output-memory.md).
From `js`:

```sh
npm run test:compat
node --expose-gc --experimental-test-coverage --test test/node.test.mjs test/compat.test.mjs
npm run benchmark:compat
```

The reference SDK owns GC-finalized native handles with no public disposal.
The differential test runner uses exposed GC after tests to finalize those
handles; no test is force-exited or skipped to hide pending work.

- **19 tests passed**: five facade/differential tests and 14 existing Worker
  tests. Facade coverage: **100% lines/functions, 96.47% branches**.
- This change only adds a Node facade and harness mode; browser code/shared
  host behavior is unchanged. The prior browser checks are not represented
  as a new browser run for this experiment.
- **54 measured operations** passed: two sizes x three APIs x three iterations
  x (read + buffer sign + file sign). **All 36 measured sign outputs** were
  independently Trusted in both readers, with one callback each.
- Runtime: Node **24.18.0**, macOS arm64.
- Reference: c2pa-node **0.9.10**, c2pa-rs **0.91.3**, commit above; native hash
  `f357e42770bc0e5c521a1593cdca966eb07eabd181c2b0ea75a1c3c3b28c650f`.
- Final receipt: ignored `js/results/compat-node.json`, completed
  **2026-10-17T00:13:24.000Z**.
- Receipt SHA-256:
  `e423e31e9dfd203d20e0f0129fcd47754acd5b52a45da6cef6477c1e7cad7cee`.
- Facade SHA-256:
  `f01054b4d66301e539f936b989e3d6427dd712d00d11d9220a345957f54119b4`.

All recorded source/reference artifact fingerprints were checked against disk.
Benchmark scratch files are removed. Raw receipt includes samples, input
hashes, output lengths, memory baselines/high-water, provenance and validation.

## Performance/memory method and results

Reuses [path-node.mjs](../benchmarks/path-node.mjs) with `--compat`: raw Worker,
facade and reference SDK, all with file-path inputs. Sizes are the SDK's
61,720-byte thumbnail JPEG and the same file padded to 64 MiB.

Each sample uses its own child process, matching small-operation warmup,
then main-isolate GC before baseline, and no forced GC during measurement.
Alternate/reverse order by iteration. Report timing includes JSON access;
signing includes builder/signer construction, certificate adaptation and
file completion for file destinations. Reference/experimental signing use the
same raw WebCrypto key/certificates but retain their different output defaults.

RSS is externally sampled through `ps` every 10 ms plus command latency and
endpoints. Tables show **process-lifetime OS high-water RSS**, including
startup/warmup. Parent cross-validation and later buffered-result persistence
are outside timing/sampling. File output is not an `fsync` durability test.

Median latency, milliseconds:

| Size / operation | Raw Worker | Facade | Existing SDK |
| --- | ---: | ---: | ---: |
| Small read | 1.27 | 1.57 | 1.20 |
| Small sign to Buffer | 1.46 | 1.76 | 14.44 |
| Small sign to file | 2.52 | 2.92 | 15.11 |
| 64 MiB read | 45.89 | 44.67 | 53.77 |
| 64 MiB sign to Buffer | 101.57 | 100.59 | 106.49 |
| 64 MiB sign to file | 121.07 | 115.70 | 107.50 |

Median process peak RSS, MiB:

| Size / operation | Raw Worker | Facade | Existing SDK |
| --- | ---: | ---: | ---: |
| Small read | 70.6 | 70.7 | 71.1 |
| Small sign to Buffer | 70.8 | 71.0 | 76.9 |
| Small sign to file | 70.7 | 70.8 | 76.4 |
| 64 MiB read | 104.6 | 102.0 | 135.1 |
| 64 MiB sign to Buffer | 498.9 | 515.1 | 397.0 |
| 64 MiB sign to file | 157.5 | 158.1 | 332.5 |

Small calls show roughly 0.3-0.4 ms additional median time through the facade
in this run. Large calls do not resolve its overhead: apparent negative
overhead is noise, not a speedup caused by an extra layer. File-output memory
behavior remains close to the raw API. Buffered large outputs remain costly;
the facade does not remove those copies.

## Migration gaps and decision

Not implemented: full Settings/Context normalization/defaults, URL trust
resolution, legacy settings strings/TOML, native handles/resources,
`remoteUrl/isEmbedded`, detached/remote manifests, LocalSigner, other algorithms,
direct COSE, timestamps/identity, builder mutation/archive/ingredients/resources,
the upstream 10 GB reader limit/error class, or exact Rust-derived error
strings/report fields. Definitions must supply the existing baseline IDs.

The [known action-validation gap](2026-10-16-validation-parity.md) is unchanged.
The facade reports what Rust returns; no JS action-validation shim is added.
Errors are required to reject, but generic native reference errors are not
rewritten into a fabricated identical Rust error vocabulary.

Three samples, one machine, warm cache, synthetic large JPEG padding, sequential
work and differing SDK validation/defaults limit conclusions. RSS is not an
allocation trace, retention/leak proof or constant-memory guarantee.

**Decision:** the namespace is a useful opt-in migration seam for existing
baseline client code, with explicit ownership and unsupported-feature failures.
It is not ready to replace the package import globally. Future experiments
should close a named **binding** gap with preserved Rust behavior and a paired
client contract, or measure a specific boundary-copy optimization.
