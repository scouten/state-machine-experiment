# Adobe-shaped Reader: differential read corpus

A private, read-only JavaScript prototype above this repository's existing
Rust state-machine SDK. It adds no Rust workflow, I/O loop, platform service,
or dependency on another checkout.

The proof covers **seven inputs and nineteen fixture/policy combinations**:
legacy v1 and v2 JPEGs, an older timestamped JPEG, JSON assertions and actions,
present/absent thumbnails, TIFF and unsigned JPEG. Both Node and browser entry
points report complete stores, extract resources, preserve unsigned-asset
`null`, and reject genuine failures. Trust-disabled, untrusted and explicitly
trusted reads are separate cases, not interchangeable successes.

## Run

Use Node 22+ and the prerequisites for the
[browser SDK](../c2pa-js-state-machine/README.md#run) and
[Node addon](../c2pa-node-compat-addon/README.md). From the repository root:

```sh
npm --prefix c2pa-node-compat-addon run build
npm --prefix c2pa-js-state-machine ci --ignore-scripts
npm --prefix c2pa-js-state-machine run build:wasm
npm --prefix adobe-js-state-machine ci --ignore-scripts
cd adobe-js-state-machine
npm exec playwright install chromium firefox webkit
npm run typecheck
npm test
npm run test:browser
```

The Node corpus also runs in the existing Node-addon CI job. Browser checks are
an explicit local command, like the underlying JS migration experiment.

The package exports TypeScript source for this experiment; it is not a compiled
or published distribution. The two local package dependencies stay within this
repository. Browser tests use this repository's JPEG, not a separately downloaded
source checkout.

## Node

```ts
import { C2paReader } from "adobe-js-state-machine/node";

const reader = await C2paReader.fromAsset({ path: "photo.jpg" }, { trust: false });
if (reader) {
  console.log(reader.getActive()?.title, reader.json().validation_state);
}
```

`{ buffer, mimeType }` is also supported; buffers require an explicit MIME type.
Files without an extension are detected by the existing host's content sniffing.
`json`, `activeLabel`, `getActive`, `isEmbedded`, `remoteUrl`, and
`resourceToAsset` delegate to the existing Node reader. Composition preserves
the backend's private fields rather than copying a native-backed instance or
changing its prototype. Node owns asynchronous file operations; Rust remains
synchronous and sans-I/O.

To verify trust, pass caller-supplied PEM material instead of `trust: false`:

```ts
const reader = await C2paReader.fromAsset(
  { path: "photo.jpg" },
  { trust: { trust: { trustAnchors: certificatePem } } }
);
```

The same trust shape works in the browser factory. `trustAnchors` and optional
`userAnchors` accept inline PEM strings or arrays of inline PEM certificates.
Optional `cawgTrust` is independent. Arrays are joined locally, never interpreted
as fetch URLs. Configuration is snapshotted by browser factories; concurrent
factories with different policies remain isolated. URL-based lists, implicit
default trust and unsupported settings reject explicitly.

## Browser

```ts
import { createAdobeC2pa } from "adobe-js-state-machine/web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";

const sdk = await createAdobeC2pa({ wasmSrc, trust: false });
try {
  const reader = await sdk.reader.fromBlob("image/jpeg", blob);
  if (reader) {
    try {
      console.log(await reader.activeManifest());
      console.log(await reader.json());
    } finally {
      await reader.free();
    }
  }
} finally {
  sdk.dispose();
}
```

`activeLabel`, `activeManifest`, `manifestStore`, `resourceToBytes`, and `free`
retain their asynchronous browser shape. `json` returns a parsed **object**, as
the current browser Reader does at runtime. An explicit `workerSrc` URL selects
the existing module-Worker host; omitting it selects inline Wasm. Both paths
are tested in Chromium, Firefox and WebKit. Disposal and freeing remain the
underlying runtime's responsibility.

## What the proof establishes

- The checked-in [baseline](test/fixtures/read-contract.json) was captured by
  executing the existing Adobe Node Reader on [read.jpg](test/fixtures/read.jpg),
  with claim trust and online OCSP disabled. The asset was signed with the legacy
  Node SDK using the existing test-only ES256 certificate: one v2 manifest, one
  `c2pa.created` action, an embedded thumbnail and no timestamp or ingredients.
  It records the input SHA-256, complete report and exact thumbnail length/hash.
  It contains data only, no implementation or external source links. No private
  key or new certificate is included.
- Node compares the full report to that baseline for file, buffer and
  extensionless-file reads.
- The expanded [corpus](test/fixtures/corpus.json) contains independently captured
  complete Adobe Node Reader reports for seven assets and nineteen policy cases.
  Eighteen cases require exact full-report equality; the timestamped case has
  one explicit TSA-policy difference, described below. Its generated fixtures were signed by the legacy Node SDK, not by the reader
  under test. It includes the older timestamped v1 fixture rather than excluding
  it. JSON assertion bodies and kinds, versioned action labels, trust provenance
  and TIFF exclusion diagnostics participate in full-report comparisons.
- Every corpus case runs through both path/content-sniffed and buffer Node reads,
  and inline/Worker browser readers in Chromium, Firefox and WebKit.
- Browsers compare inline and Worker results to the same baselines **and** a
  live pinned `@contentauth/c2pa-web@0.15.3` reader: full store and `json()` object
  equality plus exact resource bytes. Baselines are not regenerated by the
  implementation under test.
- Both hosts read unsigned JPEGs as `null`. Every signed JPEG/policy corpus case
  is additionally modified outside the manifest and must report `Invalid`;
  browsers check the live legacy verdict too. Errors are not converted to unsigned results. Browser
  tests also exercise free/dispose and missing-resource errors.

**`trust: false` is not a trust verdict.** Signature/integrity verification still
runs; intact fixtures report `Valid`, not `Trusted`. Supplying the signer anchor
with trust verification enabled reports `Trusted`; empty anchors report `Valid`.
This slice does not download
default Adobe trust lists or perform online OCSP. Missing/unsupported trust
configuration and extra configuration keys reject rather than silently using a
different policy.

### Explicit timestamp policy difference

The older timestamped JPEG is retained in the matrix, but is **not counted as
exact legacy parity**. With `trust: false`, the legacy SDK reports
`timeStamp.trusted` without supplied TSA anchors. The new reader instead reports
the authenticated timestamp as valid but `timeStamp.untrusted` until actual TSA
trust is configured. It does not invent trust to match the legacy label.

The [differential expectation](test/report-contract.ts) checks exactly that
diagnostic change and full equality of everything else. Browser tests separately
check the live legacy report against the untouched captured baseline. No
production output is rewritten or normalized to hide the difference.

## Not proven yet

This is bounded corpus-backed reading parity, not the whole Adobe SDK. AI/model
helpers (`usedAiModels`, `usedAiModelNames`, `findGenAiAssertions`), default/online
trust configuration, per-read Context/settings, linked histories, other media
formats, signing, compliance and service APIs, publication, and a broader corpus
are subsequent slices. None is stubbed with a success-shaped result here.

The corpus is intentionally not a large field corpus. It does not prove linked
ingredient-history validation, all TIFF variants or every signer/timestamp chain.
The timestamped fixture currently exercises the explicit trust-disabled policy;
the newly signed fixtures exercise all three policies.
