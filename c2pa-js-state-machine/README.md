# c2pa-js state-machine prototype (M0 + M1)

This standalone, source-only package freezes the legacy SDK contract and runs
an inline browser read/sign prototype over the real state-machine Wasm engine.
It is not a published replacement SDK or a full compatibility shim. Backend
selection is explicit, with no fallback after a workflow fails.

## Run

Requires Node 22+, Rust 1.96+, the `wasm32-unknown-unknown` target, `curl`, `tar`,
and Playwright's Chromium, Firefox, and WebKit. The wasm-bindgen CLI must match
the version resolved in the workspace's Cargo lockfile. A package-local CLI
under `.cache/tools/bin/` takes precedence over the shared installation.

```sh
cd c2pa-js-state-machine
npm ci --ignore-scripts
npm run prepare:upstream
npm run inventory:check
rustup target add wasm32-unknown-unknown
# Build reports the required CLI version if your installed one does not match.
# Install that version without replacing a shared CLI:
# cargo install wasm-bindgen-cli --version <version> --locked --root .cache/tools
npm run build:wasm
PLAYWRIGHT_SKIP_BROWSER_GC=1 npx playwright install chromium firefox webkit
npm run typecheck
npm test
npm run test:oracle
npm run test:m1
npm run report:parity
```

`test:oracle` runs five original browser-reader tests in headless Chromium:
unsigned assets return `null`, asset-size errors, c2pa-rs error propagation,
freeing a Reader, and private-field enumeration/serialization. Neither their
bodies nor their assertions are rewritten. The other tests are inventoried,
not presented as passing. `test:m1` runs the same five unchanged tests plus ten
milestone-specific cases independently in Chromium, Firefox, and WebKit.

The oracle rejects missing, duplicate, skipped, or additional selected results.
Actual assertion failures are recorded and return a failing exit status.
Runtime JSON, JUnit, artifact fingerprints, observations, and the parity ledger
are written under ignored `results/`. Report generation rejects evidence from
a different inventory, dependency lockfile, harness/configuration, or backend
artifacts. Current cached upstream files are rechecked. New-backend evidence
also hashes generated JS/Wasm, build provenance, Rust inputs, and public fixtures;
changing an input requires rebuilding and/or rerunning the affected proof.

```sh
# Still deliberately exits nonzero: 244 upstream declarations remain unported.
npm run check:parity

# Explicit selection of the actual state-machine backend.
npm run test:oracle -- --backend state-machine
```

## Frozen inputs

[upstream.json](upstream.json) pins the upstream source commit, archive SHA-256,
published web SDK version/integrity, package scope, and exact oracle test names.
[package-lock.json](package-lock.json) freezes the harness and SDK dependencies.
The source revision and published SDK are independently pinned inputs: the
selected tests prove their observed agreement, not equivalence of every source
feature with the published binary.

`prepare:upstream` downloads only the public source archive to `.cache/`, verifies
it before extraction, and preserves its license/notices. Interrupted extraction
uses an owned staging directory and does not publish a partial checkout.
Cached input changes are rejected by `inventory:check` and `test:oracle`.

[contracts/inventory.json](contracts/inventory.json) records:

- Every test declaration in the pinned web, Node, utilities, and types packages,
  with file/line identity, suite/title, platform, source mode, and parameterization.
- Package manifests/export selectors, exported source declarations and member
  names, and hashes of published TypeScript declarations.
- All scoped source/fixture hashes, upstream license and lockfile hashes.

The denominator counts **declarations**, not expanded parameterized instances.
Parameterized/dynamic declarations remain visible and cannot receive a passing
observation until a later milestone expands and identifies every runtime case.
Types currently have no upstream test declarations, but their export surface and
published declaration hashes are still frozen.

To intentionally refresh a contract, change the pin and checksum, prepare the
new source, run `npm run inventory`, and review/commit the inventory and lockfile.
Do not regenerate to conceal a runtime failure. A changed frozen contract
invalidates old evidence.

## Harness-only adaptations

Vite loads the unchanged upstream reader spec directly from the verified cache.
An import adapter supplies the selected SDK's Reader/factory, test lifecycle
fixture, Wasm URL, and size-limit constant; that constant is checked against
the pinned source before running. Fixtures and expected manifest objects remain
upstream files.

The published SDK bundles utilities. Tests therefore import its public utilities
re-exports so `AssetTooLargeError` and `Context` have the same constructor identity
as the SDK itself. This is import binding, not a change to assertions.

Only three named public trust-anchor fixtures are supplied as raw virtual modules;
Vite's denial of other PEM/key files stays enabled. Failure screenshots are
disabled so the runner does not mutate frozen source/fixture hashes.

The selected backend supplies its own utility constructors. Legacy uses the
published SDK's bundled re-exports; state-machine uses the standalone utilities,
excluded from Vite prebundling so errors retain their constructor identity.

## Inline prototype

```ts
import { createC2pa, Reader, Context } from "c2pa-js-state-machine/inline";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";

const client = await createC2pa({ wasmSrc });
try {
  const reader = await Reader.fromBlob(client, blob.type, blob, new Context({
    trust: { trustAnchors: rootPem },
    verify: { verifyTrust: true, ocspFetch: false },
  }));
  if (reader) {
    try { console.log(await reader.manifestStore()); }
    finally { await reader.free(); }
  }
} finally { client.dispose(); }
```

The `/inline` entry is an explicit migration experiment, not the legacy
Worker-backed default. Reader methods are Promise-shaped; absent manifests
return `null`, size errors use the shared public class, and Reader/Builder
internals are private. JPEG can be sniffed when the format is omitted. The
compatibility adapter rejects a missing/unsupported **claim hash algorithm**
with `C2pa(UnknownAlgorithm)`; the domain engine keeps its own SHA-256 default.

`Builder.fromDefinition(client, definition)` implements the strict baseline
definition only. Its `sign(signer, format, blob)` returns `{ asset, manifest }`
as `Uint8Array`s. This is the **new baseline signer**, not legacy c2pa-web's
COSE-producing `Signer`: provide `alg: "es256"`, DER `certs`, and an async
`sign(data)` producing the 64-byte WebCrypto ECDSA signature. Keep the private
key in a non-extractable `CryptoKey`; no private key crosses into Wasm. Omitted
IDs are generated by the JS host; caller IDs are preserved. A requested
timestamp without a service fails rather than silently signing without one.

Disposal invalidates the runtime immediately. In-flight work drains and rejects
instead of publishing a handle/result; borrowed builders are freed only after
their pending operation finishes. Calling `free` is idempotent. The inline
loader shares one initialized module per realm, rejects a different resource
after initialization, and permits retry after failed initialization.

### Proof and remaining scope

The ten added cases prove actual artifact loading and failure recovery,
WebCrypto signing, trusted/no-anchor/tampered validation, bidirectional cross-read
against legacy-signed fixtures and the legacy reader, suspended read/build
interleaving, exactly-once claim-signing callbacks, host failures, unsupported
settings, missing timestamps, and disposal during pending work. Both engines'
clocks are frozen to 2026-09-01 inside the public test certificate's validity
window. The public fixture private key in generated test data is test material
only and protects nothing; never use it to sign real credentials.

The upstream denominator is still **249 declarations**: five new-backend passes
require all three browsers; 244 remain unported. The separate M1 gate records
45 executions (15 selected cases per browser) without inflating parity.

Not yet supported: Worker hosting/configuration, full manifest/assertion and
resource reporting, broad/global settings, remote manifests, online OCSP,
non-JPEG formats, full legacy builder/signer APIs, or published distribution.
Explicit Context inputs outside PEM trust anchors, enabled trust verification,
and disabled OCSP reject rather than pretending to be honored. M1 proves
missing-service timestamp failure; a deterministic TSA success fixture remains
required when a browser transport is introduced.

See the [migration plan](../docs/js-migration-plan.md) for M2+ acceptance gates.
