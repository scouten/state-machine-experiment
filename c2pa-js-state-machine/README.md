# c2pa-js state-machine prototype (M0 + M1 complete; M2/M3 in progress)

This standalone prototype freezes the legacy SDK contract and runs
inline and module-Worker browser read/sign prototypes over the real state-machine Wasm engine.
It is not a published replacement SDK or a full compatibility shim. Backend
selection is explicit, with no fallback after a workflow fails.

The current priority is [binding feasibility](../docs/js-migration-plan.md#current-priority-binding-feasibility-not-rust-feature-parity):
wrap the Rust capabilities that exist, verify FFI/host behavior, and measure
whether the hosting model is effective. Missing Rust domain features are
tracked dependencies, not tasks to implement as part of each wrapper slice.
The full-parity ledger remains a separate long-term compatibility measure.

The out-of-scope ingredient manifest-link validation experiment was removed
from this branch on 2026-10-15. Linked-history reporting remains explicitly
unsupported. Retained core result/settings seams support the existing binding
demonstrations; they are not a commitment to extend domain coverage here.

## Run

Requires Node 22+, Rust 1.96+, the `wasm32-unknown-unknown` target, `curl`, `tar`, OpenSSL 3,
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
npm run test:m2
npm run test:m3
npm run test:package
npm run test:performance
# Repeat the same two cases on all browser engines:
npm run test:performance -- --all-browsers
npm run report:parity
```

`test:oracle` runs seventeen original browser-reader tests in headless Chromium:
unsigned assets return `null`, asset-size errors, c2pa-rs error propagation,
freeing a Reader, private-field enumeration/serialization, and exact embedded
thumbnail extraction, active/store reporting, Context ownership and factory settings.
Neither their
bodies nor their assertions are rewritten. The other tests are inventoried,
not presented as passing. `test:m1`, `test:m2`, and `test:m3` each rerun the
same seventeen unchanged tests on **both inline and Worker**, plus all declared
state-machine browser cases, in Chromium, Firefox, and WebKit. The upstream
matrix has 102 executions (seventeen cases × two runtimes × three browsers).
The parity report's `readerRuntimes` gate records these separately from unique
upstream declarations: seventeen passes remain seventeen, not 102.
The parity report separates M1, M2, and M3
counts and outcomes. M3 covers caller-supplied detached manifest bytes,
malformed-store rejection, and `Builder.signDetached`: the browser test removes
the fixture's C2PA APP11 segment, confirms the output asset is byte-for-byte
unchanged and has no active embedded manifest, then reads the detached store as
`Trusted`. A modified asset is not trusted. M3 also covers JPEG XMP remote
discovery and policy-bounded browser transport through loopback test servers:
default-off fetching, trusted/tampered reads, embedded/detached precedence,
destination denial, redirect/HTTP/size/malformed failures, header/body deadlines,
caller cancellation, CORS denial/success, and explicit retry.

M3 also proves an opt-in browser OCSP POST host with genuine signed responses,
using ephemeral TEST ONLY keys/certificates. The test clock is fixed just after
response generation, inside its validity window; no public responder is contacted.
Success records `ocsp.notRevoked`; authenticated revocation invalidates the
asset. Policy/CORS/HTTP/size/deadline/abort failures and unauthenticated DER record
`ocsp.inaccessible` and preserve the existing fail-open validation policy.
Classic TIFF and BigTIFF in both byte orders now sign/read through the registry,
with header sniffing, detached read-back, two separate exclusions, pixel-tamper
proof, and legacy validation of classic TIFF output. DNG coverage is aliases only.

### Embedded resources

Both reader entries support `await reader.resourceToBytes(identifier)`. The
claim thumbnail now appears in `activeManifest()`, `manifestStore()`, and `json()`
with legacy-shaped `{ format, identifier }` metadata. The identifier is an
absolute `self#jumbf=/c2pa/<manifest>/c2pa.assertions/<assertion>` URI. Binary
assertions are decoded by Rust, not reparsed or fetched by JavaScript. Results
are independent `Uint8Array` copies; missing, ambiguous, relative, or external
identifiers reject. Free/dispose checks still apply. Extracted bytes do not
imply trust: consult validation results. The reader retains resource payloads
in memory; it does not buffer the whole asset or issue extra asset reads.

The unchanged upstream thumbnail test now increases unique feature coverage
from **5/249 to 6/249**. Additional browser proof compares metadata and exact
bytes with legacy, exercises copy ownership and failed-lookup recovery, and
checks lifecycle errors. The installed private-package consumer also extracts
the thumbnail on every inline/Worker URL/module path. Linked ingredient
resources/history, databoxes, external resources, `crJson`, and full report parity
remain open.

Claim-generator icons now project the same `{ format, identifier }` reference
when they target an embedded assertion in their owning manifest. Relative claim
references become exact absolute IDs; already absolute same-owner references
are accepted. Missing, ambiguous, cross-manifest, external and deprecated databox
targets fail reporting explicitly, rather than silently dropping the icon or
fetching anything. Modern icon metadata and bytes match pinned legacy on inline
and Worker, including complete trusted stores and parsed JSON. Tampering still
reports `assertion.hashedURI.mismatch`; extraction is not a trust verdict.
An identical icon/assertion hash reference is checked once, but conflicting
hashes or algorithms remain separate checks.

The v1/v2 icon, ingredient-thumbnail and ingredient-data test assets, plus the
v2 detached-data asset/sidecar and trusted report golden, were signed/generated
by real c2pa-rs using only the repository's TEST ONLY credential. To regenerate
from the repository root:

```sh
openssl x509 -inform DER -in contentauth-c2pa-builder/tests/fixtures/test-signer.der -out /tmp/m3-icon-signer.pem
cargo run --manifest-path c2pa-rs-compat-conformance/Cargo.toml --example generate_resource_fixtures -- /tmp/m3-icon-signer.pem c2pa-js-state-machine/browser/fixtures
rm /tmp/m3-icon-signer.pem
```

The v2 fixture proves exact icon extraction in installed packages and shared
reporting through the actual Node addon. The v1 fixture proves the databox
boundary remains explicit and readers recover for subsequent supported input.
The separate Node addon now exposes these retained resources through
`resourceToAsset(uri, { buffer: null })` or `{ path }`, using the same strict URI
lookup. Buffer results are independent copies; file writes are asynchronous JS
host operations. Its reader retains a private native handle until garbage
collection. Source closure, legacy buffer/file result shapes, exact fixture bytes,
tamper isolation and error/retry are tested in Node. This is bounded resource
support, not full Node SDK parity or large-resource streaming.
The Node facade also supports `fromManifestDataAndAsset` for caller-supplied
sidecars, reusing the same detached file session as the browser. A real c2pa-rs
store-free JPEG and trusted report golden prove complete report equality,
retained resources, byte-snapshot isolation, tamper failures and explicit-store
precedence/recovery. These actual-Node adapted cases do not add frozen upstream
passes or imply full Node settings/Context/size-limit parity.
These are migration-specific cases, not additional frozen upstream passes.

Ingredient thumbnails now use that same exact-owner resource resolver.
Supported v1/v2/v3 ingredient assertions expose a legacy-shaped `thumbnail`
reference when it names an embedded assertion in the owning manifest, including
positional resource IDs. Real c2pa-rs v2 claims prove complete trusted
active/store/parsed-JSON equality and exact independent bytes for two ingredients
on inline and Worker. A modified thumbnail reports a live hash failure and
does not change the second thumbnail. Installed package paths prove extraction
and shared Node reporting retains both references. Null thumbnails are omitted;
malformed hashed URIs, missing/ambiguous resources, external/cross-owner targets
and deprecated databox thumbnails fail explicitly. The real v1 databox fixture
proves cleanup/retry. This does not enable linked ingredient histories,
redactions or builder resource-writing APIs.

Ingredient `data` resources now reuse that resolver too. A real c2pa-rs v2
fixture contains two positional `c2pa.embedded-data` assertions, with a thumbnail
on the first ingredient. Complete trusted legacy object/JSON reports and exact
independent data bytes match on inline and Worker. Changing one data payload
retains live hash failures without changing the other data or thumbnail.
Installed packages verify both resource kinds coexist, and Node shares their
metadata. Native v1/v2/v3 tests retain exact-owner/malformed/ambiguous boundaries
and linked-history guards. Null data is omitted; databox, cross-manifest and
external data still reject explicitly. A v1 databox-data fixture proves release
and subsequent-read recovery. This is resource reporting/extraction, not full
ingredient-link/hash, history or redaction validation, and extraction never
grants trust or parses the data as a trusted object.

### Active-manifest and complete-store reporting

The original upstream active-manifest equality and trusted/untrusted complete-store
tests and blob-creation store golden now pass unchanged. With omitted-format
detection, explicit/reused/independent Contexts and deprecated reader-factory
creation/merging, unique upstream coverage is **17/249**, including the unchanged
disabled-trust store golden.
Claim-generator extensions, verified
claim and CAWG X.509 signer metadata, unsigned decimal certificate serials,
and authenticated RFC 3161 times are projected by Rust. The legacy `issuer`
field means the signer's **subject organization**, not its certificate issuer.
Known hard-binding and embedded-resource assertions stay in the raw core report
but are excluded from the compatibility assertion list.

Inline and Worker report the same active manifest via `activeManifest()` and
`manifestStore()`. Browser tests compare the entire active manifest
with legacy, then prove independent claim/identity anchors can establish trust
without changing that metadata. Installed-package paths check signer metadata
and reporting consistency too. Metadata is not a trust verdict: an authentic
timestamp from an unanchored authority does not supply trusted validation time.
The identity report's legacy `revocation_status: true` denotes a verified
credential, **not** a performed OCSP check; actual validation statuses remain
authoritative. Unsupported directory-string encodings are not projected.

Single-manifest complete stores match legacy on both runtimes, including stable
status phase ordering, failure-only top-level summaries, and scoped named
claim/timestamp trust lists. All observations remain in the result buckets.
CAWG distrust is a compatibility failure without lowering store validation state;
tampered resources still expose their actual failures and unrelated successes.
Parsed `json()` now matches legacy's trusted/untrusted single-manifest reports.
It intentionally differs from the object APIs: every nonempty all-number array
in an object field becomes padded standard base64, regardless of its name.
Legacy's display formatter uses unsigned integers' low byte and omits negative
and floating-point entries; empty/mixed/direct nested arrays remain arrays.
Newly signed assertions verify those quirks against legacy, while repeated JSON
calls leave object views unchanged. Installed packages verify array/base64 hash
views on every loader path. Rust JS/Node hosts share the formatter; serialization
errors propagate through bindings rather than returning `"{}"`.
JSON parity here means parsed values, not whitespace/key-order byte equality.
Disabled claim-trust settings and independent CAWG anchor switches are supported
as described below. `crJson`, linked ingredient history/deltas and broader
resource references remain separate parity work.
No legacy fallback or default-backend change is introduced.

### Resource-free ingredient reporting

Signed v1, v2 and v3 ingredient assertions now appear in legacy-shaped
`ingredients`, not as generic `assertions`. The shared Rust JS/Node projection
preserves assertion order, positional labels, relationships, titles, format and
instance identifiers, version-appropriate document IDs, descriptions,
informational URIs, digital source types and data types. Empty optional
ingredient lists remain omitted, preserving existing single-manifest goldens.
These are assertion metadata, not proof that the ingredient asset was supplied
or validated.

The core records `ingredient.unknownProvenance` for `parentOf`/`componentOf`
ingredients declaring no source manifest; `inputTo` is exempt, matching legacy.
The adapter scopes those new informational observations to owner-qualified
`ingredientDeltas`, never substitutes them for active signature/integrity
findings, and does not lower a valid/trusted outcome merely for unknown
provenance. Complete object and parsed JSON reports for a newly signed
four-ingredient asset match legacy on inline and Worker. Tampered ingredient
bytes still report the actual hashed-URI mismatch.

Ingredient assertion `metadata` now supports creation-time text (`dateTime`),
review ratings (`reviewRatings`) and custom extension fields. Full legacy
object/JSON comparisons cover all three ingredient versions, empty/null optionals,
ignored unknown review fields and extension numeric-array/base64 formatting.
Reviews are signed opinions, not live validation or proof of source authenticity.
Their unsigned-byte encoding is checked (0-255, like legacy), not the truth of a
review or the recommended 1-5 scale. Creation time is not a trusted clock or an
authenticated timestamp. Tampering with a review still invalidates its assertion
hash; a review code cannot cancel or inject validation observations.

This is not linked-manifest or historical-delta parity. Ingredients containing
`activeManifest`, `c2pa_manifest`, `claimSignature`, unsupported resource targets,
structured metadata (`reference`, `dataSource`,
`localizations`, `regionOfInterest`), or recorded validation fields reject
explicitly when a compatibility object/JSON report is serialized. Unsupported
numeric versions and malformed supported fields also reject; malformed optional
fields are not silently dropped as the legacy decoder may do. Raw engine
assertions remain available to native hosts. Readers can still be freed after
reporting errors and later supported reads succeed. No ingredient network reads,
legacy fallback, automatic host-ID generation or high-level ingredient-building
API is added. These additional differential cases do not increase the frozen
upstream declaration count, which is **17/249** after the Context/factory slice.

### Context ownership and incremental migration

Six additional unchanged upstream reader declarations cover omitted-format
detection, explicit Context application, independent Contexts on one runtime,
memoized Context reuse, deprecated factory creation and per-call settings
precedence. All 17 selected declarations run through inline and module Worker in
Chromium, Firefox and WebKit (102 runtime executions); the frozen 249-declaration
denominator is unchanged. The six remaining reader declarations are fragmented
BMFF reads/limits, the upstream remote-manifest case and fragmented factory
creation. The dedicated upstream inline entrypoint remains separate work.

Both static reader paths now call the caller's `Context.toJson()`. The Worker
receives its resolved JSON rather than rebuilding and re-resolving a Context
from raw settings. Reusing a Context shares the pinned utility's memoized
Promise, including its cached policy if the caller later mutates the original
settings. Construct a new Context to change that policy. Overlapping readers
with opposite trust policies remain independent; loader defaults still apply
only to deprecated factory reads, not static constructors.

Context-resolution failures reject the read before dispatch, and disposal while
resolution is pending prevents a later Worker read. Supported retries remain
possible. The private Worker protocol is now v2: stale v1 scripts fail startup
explicitly instead of silently ignoring cached Context semantics. Ship client
and Worker from the same build. There is no automatic fallback or backend
promotion; callers can keep choosing legacy during migration. Installed
URL/precompiled-module package paths prove concurrent Context isolation and
cached-policy reuse too.

### Opt-in network hosts

`Reader.fromBlob(runtime, format, blob, context?, detachedManifest?,
remoteManifestOptions?, ocspOptions?)` and
`runtime.reader.fromBlob(format, blob, settings?, detachedManifest?,
remoteManifestOptions?, ocspOptions?)` accept separately authorized host options:

```ts
const ocsp = { allowedOrigins: ["https://ocsp.example"], maxBytes: 64 * 1024, timeoutMs: 5000 };
const reader = await Reader.fromBlob(runtime, "image/tiff", blob, context, undefined, undefined, ocsp);
```

Both option types require exact canonical origins, a positive byte limit, a
positive deadline, and optionally an `AbortSignal`. Options explicitly opt that
operation into fetching, overriding a Context's disabled flag. `ocspFetch: true`
without OCSP options still rejects rather than silently using an offline host.
Remote manifests require HTTPS except explicitly listed loopback HTTP origins;
OCSP allows explicitly listed HTTP responders because response signatures are
verified by Rust. Browsers still enforce CORS and mixed-content policy. Neither
transport sends credentials/referrer or follows redirects. Allowlisting an origin
is caller authorization, not a guarantee that the service is trustworthy.
Cancellation ends the network operation, not necessarily the entire read: OCSP
failures are reported as inaccessible, while remote-manifest failures reject.

### Explicit Worker hosting

The `c2pa-js-state-machine/worker` entry exports `createC2pa`,
`Reader`, `Builder`, and `Context` with the implemented inline operation shapes.
The inline entry remains inline-only; changing imports is an explicit migration
choice, not a fallback. With a Vite-style module-Worker bundler:

```ts
import { createC2pa, Reader } from "c2pa-js-state-machine/worker";
import workerSrc from "c2pa-js-state-machine/worker-entry?worker&url";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";

const runtime = await createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href) });
try {
  const reader = await Reader.fromBlob(runtime, undefined, asset);
  try { console.log(await reader?.json()); }
  finally { await reader?.free(); }
} finally { runtime.dispose(); }
```

`wasmSrc` also accepts a precompiled `WebAssembly.Module`. Relative Wasm URLs
resolve against the caller page. Each runtime owns a separate Worker/Wasm realm,
with a readiness handshake and a 30-second initialization deadline. The caller
must supply the module Worker URL; there is no generated Blob script, classic
Worker loader or automatic backend retry.

Wasm handles, Blob reads, hashing, and bounded remote/OCSP fetches stay inside the
Worker. Signing and timestamp callbacks run on the caller thread, so a
non-extractable signing key need not leave it. Operation IDs route callbacks;
private resource proxies prevent accidental handle serialization. Network options
are copied, and caller AbortSignals are forwarded as cancellation messages.
OCSP cancellation preserves the same inaccessible-response policy as inline.

`free()` is idempotent, rejects subsequent use, and closes a busy builder once
its callback settles. `dispose()` terminates the Worker and rejects all pending
operations immediately. It cannot cancel a caller's arbitrary signing Promise;
a late callback result is ignored after disposal. Structured cloning currently
copies byte arrays without detaching caller buffers; output-copy and large-asset
memory costs remain unmeasured. Blob subclasses/custom `slice()` overrides are
not retained by structured cloning.

Three-browser proof covers URL/module loading, failed-loader retry, signed and
detached reads, callback failures, in-flight free/disposal, remote cancellation,
signed OCSP outcomes, and external-module CSP allow/deny behavior. The CSP fixture
allows `script-src 'self' 'wasm-unsafe-eval'`, `connect-src 'self'`, and
`worker-src 'self'`, with no inline/eval/Blob script allowance; `worker-src 'none'`
fails explicitly. Production pages must authorize their actual Worker/Wasm and
network origins. Registry publication, broader bundler compatibility and full
upstream Worker parity remain open.

The Worker timestamp slice uses an ephemeral local RFC 3161 authority: OpenSSL
signs and independently verifies a response for each actual SHA-256 request.
Three-browser tests prove concurrent operation routing, definition `tsa_url`
precedence over the signer's URL, and timestamped embedded JPEGs reading back
`Trusted` with `timeStamp.validated` in Worker, inline, and the pinned legacy SDK.
Detached timestamped output cross-reads through Worker and inline unchanged.
Missing callbacks, authority refusal and malformed responses fail explicitly;
the same builder can retry successfully.

A genuine token for a different imprint is rejected as trusted time and reported
as informational `timeStamp.mismatch`, with no `timeStamp.validated`. The reader
then uses its host clock; an otherwise currently trusted manifest remains
`Trusted`. This preserves the existing validator policy, not an untimestamped
signing fallback. Tests use real-clock Workers with fresh certificates rather
than the frozen-clock fixtures. This is local RSA/SHA-256 TSA interoperability,
not public TSA, expired-signer longevity, or broader algorithm coverage.
The caller still owns timestamp transport; no default network host is introduced.

### Reader factory settings compatibility

Both loaders accept the supported reader subset in `settings`. As in the pinned
legacy SDK, these defaults apply to `runtime.reader.fromBlob(...)`, **not** static
`Reader.fromBlob(runtime, ..., context)`. The factory uses the existing utilities
`mergeSettings` helper: per-read fields override defaults without dropping other
fields in a section. Its array merge semantics are preserved; `[]` does not
reliably clear inherited anchors. The tested clearing override is
`{ trust: { trustAnchors: "" } }`.

Supported defaults are `trust`/`cawgTrust` `trustAnchors` and `userAnchors`
(strings or string arrays), boolean `verify.verifyTrust`, boolean
`trust.verifyTrustList` / `cawgTrust.verifyTrustList`, and `ocspFetch`. Anchor
serialization/resolution still uses the existing Context utilities.
`verifyTrust: false` disables only claim anchor verdicts: signature, certificate
profile/path/validity, binding, timestamp and revocation checks still run.
It cannot produce `Trusted`. The pinned utilities implement `verifyTrustList: false`
by omitting that kind's anchors, not by disabling validation: CAWG may still report
`cawg.x509.credential.untrusted`. Compatibility CAWG failures cap an otherwise
trusted report at `Valid`, without lowering the engine's independent claim state.
Unknown fields and unsupported values reject. `ocspFetch: true` never grants
network access by itself: a read must supply explicitly authorized OCSP host
options, or override it to `false`. Static Context behavior and default-off
network access are unchanged.

Unlike the legacy factory's retained settings object, the new loaders snapshot
defaults at creation. Later input mutation cannot alter that runtime or another
runtime; per-read merges are also independent. To change defaults, create a new
runtime or pass a per-read override. This intentional isolation difference is
covered by tests.

This is **reader-factory compatibility**, not full global-settings parity.
`runtime.builder.fromDefinition` rejects when the runtime has nonempty defaults,
rather than ignoring settings the builder does not implement. Static
`Builder.fromDefinition` remains available and, like legacy static constructors,
does not inherit loader defaults. Builder settings are a later migration slice.
Three-browser comparisons exercise real legacy factory/static behavior,
snapshot isolation, explicit failures/retry, and authenticated inherited OCSP.
The installed private-package consumer also uses inherited reader settings.

### Private package and production-bundler proof

`npm run build:package` emits ESM JavaScript and declarations, then stages the
generated Wasm bindings and binary under `.cache/package/dist`. It checks the
Rust/Wasm provenance before building; stale generated bindings require
`npm run build:wasm`. The source harness exports remain unchanged.
The staged manifest exports `./inline`, `./worker`, `./worker-entry`, and
`./resources/state-machine.wasm`, with the existing pinned utilities package as
a runtime dependency. It stays **private**: this is not a registry release.

`npm run test:package` builds, packs and installs that npm archive in a fresh
temporary consumer **outside the repository**, with no source aliases or
workspace links. Installation uses the local npm cache offline; run `npm ci`
first to populate it. The consumer resolves emitted declarations with TypeScript,
builds with Vite 6.3.6 in production mode, and serves only the built output.
Chromium, Firefox and WebKit each exercise four paths in separate page realms:
inline/Worker with URL/precompiled Wasm. Proof includes caller-owned signing,
trusted cross-read, byte-identical detached output, malformed rejection and
resource cleanup. The packaged Worker entry is tested both directly and through
a test-only frozen-clock bootstrap for the signing fixtures.

Only the manifest and compiled `dist` files enter the archive; source harness,
fixtures and test keys are excluded. The isolated consumer supplies test fixtures
separately. Temporary installs, archives and servers are cleaned up; strict
fingerprinted evidence is written to ignored `results/package.json` and reported
as a separate `packaging` gate in the parity ledger, not extra upstream passes.
Missing, stale or incomplete evidence cannot become a successful packaging gate.

This proves one private ESM/Vite distribution shape, not npm publication,
CommonJS, classic Workers, other bundlers, or full SDK compatibility. Existing
source-only development remains available, and users still select the backend
explicitly; no automatic rollout or contraction follows from packaging.

The oracle rejects missing, duplicate, skipped, or additional selected results.
Actual assertion failures are recorded and return a failing exit status.
The state-machine oracle first runs the selected cases and milestone tests with
the inline upstream bridge, then runs the same untouched upstream selection
through the module-Worker bridge. No assertion/body edits or fallback are used.
Worker JSON/JUnit files use a `state-machine-worker-` prefix. The evidence's
`runtimeRuns` must contain all six runtime/browser combinations and exactly the
selected IDs; aggregate upstream outcomes must agree with that matrix.
Missing, duplicate, skipped or inconsistent runtime evidence fails closed.
Remaining upstream report/resource/fragment cases are still unported, not
silently skipped from the frozen denominator. This slice expands runtime proof,
not full report compatibility.
Runtime JSON, JUnit, artifact fingerprints, observations, and the parity ledger
are written under ignored `results/`. Report generation rejects evidence from
a different inventory, dependency lockfile, harness/configuration, or backend
artifacts. Current cached upstream files are rechecked. New-backend evidence
also hashes generated JS/Wasm, build provenance, Rust inputs, and public fixtures;
changing an input requires rebuilding and/or rerunning the affected proof.

### Host-boundary performance experiment

`test:performance` compares the pinned legacy Worker SDK with the state-machine
inline and module-Worker facades, plus a **test-only read-ahead Worker**,
using identical unsigned and trusted signed JPEG
bytes, anchors, settings, and frozen validation time. Signing, fixture loading,
and Wasm setup are outside the warmed read timings. Each series uses two warmup
reads and ten measured reads, rotating four-path order, with natural, zero-delay
control, and test-only 2 ms/read delay modes. Every read must return `null` for
the unsigned case or the same trusted manifest label for the signed case.

Test-only instrumentation counts actual Blob reads, requested/returned bytes,
read sizes, sync/async transport counts, and host service duration, separately
from total caller-observed read duration. It asserts the current fixture baselines: legacy
reads the asset once in both cases; state-machine reads 10 ranges totaling 38
bytes for the unsigned case and 15 ranges totaling asset length plus 38 bytes
for the signed case, identically in inline and Worker. Counts and byte totals must stay the same across repetitions
and delay modes. Deliberate implementation/fixture changes require reviewing
these expectations, not automatically accepting a new baseline.

Ignored `results/performance.json` records raw samples, median/p95 summaries,
browser user agent, asset hashes, initialization/first-operation timings,
input fingerprints, and limitations. Timing is evidence, not a test threshold.
The new Worker is instrumented **inside its realm**, since structured cloning
does not preserve caller Blob subclass hooks. A test-only entry patches Blob
reads, fixes the clock, and returns one aggregate telemetry packet before each
read result. The production Worker protocol/entry is unchanged. Operation IDs
match packets to reads, and the configured delay is checked. Caller-to-Worker
commands, replies, and test-only telemetry are counted separately, excluding
later manifest queries and `free()`. Each new Worker read must use one command,
one reply, and one telemetry packet: the 10/15 Blob reads are *inside* the
Worker, not 10/15 cross-thread calls. A Worker-local execution span is recorded
alongside caller duration; their difference is not pure FFI cost.

This is **not an isolated FFI benchmark**: Worker location is now matched, but
the Wasm implementations, loaders and I/O models are not. Legacy uses
whole-Blob synchronous reads; state-machine reads Blob slices asynchronously
and currently serially. The
synthetic delay uses a busy wait in the legacy Worker and an awaited timer on
state-machine, so it demonstrates per-request latency amplification, not native
throughput or equivalent scheduling. Instrumentation overhead is included.
Both Worker backends emit one telemetry packet per operation on these fixtures;
inline records locally. Fresh Worker setup can use warm browser Wasm/network
caches; inline Wasm is shared within a realm. Startup numbers are not cold-start
distributions. Ten warmed samples are exploratory, not a production budget;
large-asset memory and event-loop responsiveness are not measured here.

The schema-v3 report includes all four paths, exact output-shape checks,
initialization/first-operation timings, Worker message counts and Worker execution
durations. Report generation rejects missing paths/modes/samples, invalid timings,
and changed read/byte baselines; unit tests exercise malformed evidence.

Earlier matched-path natural medians from 2026-10-13 (before read-ahead), milliseconds; columns are
**legacy Worker / new inline / new Worker**:

| Browser | Unsigned | Trusted signed |
|---|---|---|
| Chromium | 0.30 / 1.80 / 1.35 | 2.75 / 3.90 / 3.40 |
| Firefox | 0.50 / 1.00 / 1.50 | 24.00 / 13.50 / 14.00 |
| WebKit | 1.00 / 3.00 / 4.00 | 4.00 / 5.00 / 7.50 |

These are a recorded run, not stable performance rankings. New Worker placement
does not add per-read cross-thread hops, but does not eliminate serial Blob-read
latency: with 2 ms/read injection its unsigned/signed medians were 28.55/43.60 ms
in Chromium, 29.00/53.50 ms in Firefox, and 30.50/48.00 ms in WebKit. Timer versus
busy-wait injection is still not equivalent scheduling. No chunk-size or default
backend change follows from this evidence.

#### Bounded host read-ahead experiment

The additional test-only Worker wraps each source Blob with a fresh single-window
cache: a miss for a request of **64 bytes or fewer** reads up to **4,096 bytes**
starting at that request's offset. Contained requests get copied bytes from that
window; requests larger than 64 bytes bypass it unchanged. The cache is scoped to
one read operation and cannot leak across assets. This does not change the Rust
session's requests, hash chunks, production loader, or production host.

The report separates **logical request sizes** from **physical Blob read sizes**,
cache hits/fills/bypasses, and maximum resident cache-window bytes. With these
fixtures all browsers assert:

| Case | Logical requests (unchanged) | Physical reads: plain / read-ahead | Physical bytes: plain / read-ahead |
|---|---:|---:|---:|
| Unsigned | 10 | 10 / 1 | 38 / 4,096 |
| Trusted signed | 15 | 15 / 4 | 88,525 / 92,559 |

Both fill one 4 KiB window; unsigned has nine hits, signed eleven hits plus
three bypasses. The signed bypass sizes remain **1,849, 65,536 and 21,078 bytes**.
Fewer reads are bought with extra bytes, especially significant for the unsigned
case. This is not whole-asset buffering, but cache occupancy is not proof of
total process memory: output copies, in-flight reads and Wasm remain separate.
The measured host services requests serially; concurrent replacement fills can
temporarily keep more than one buffer alive.

Browser checks compare complete signed/tampered projections with plain Worker
results, require tampered assets to be `Invalid`, and require malformed input to
reject. Unit tests prove exact bytes, cache eviction, EOF/empty/negative slices,
large-read bypasses, source isolation, output-copy isolation, failed/short read
propagation and retry, and concurrent ranges/pending-fill sharing.

The benchmark includes **720 measured samples**, with the same two warmups and
ten samples per case/path/mode/browser. Natural timing is exploratory; synthetic
delay applies to physical reads, not cache hits. Stronger results under injected
latency do not prove a natural-host or remote-storage speedup.

Recorded read-ahead experiment medians, before the timestamp slice
(milliseconds, plain Worker / read-ahead Worker):

| Browser | Unsigned natural | Signed natural | Unsigned 2 ms/read | Signed 2 ms/read |
|---|---|---|---|---|
| Chromium | 1.25 / 1.30 | 3.20 / 3.40 | 28.30 / 5.35 | 44.05 / 16.35 |
| Firefox | 1.50 / 1.00 | 13.50 / 13.00 | 28.50 / 5.00 | 54.00 / 25.50 |
| WebKit | 4.00 / 2.00 | 7.00 / 4.00 | 32.50 / 5.00 | 48.00 / 15.00 |

The natural Chromium samples are slightly slower with read-ahead; the larger
synthetic-delay improvement is evidence of fewer latency-bearing physical reads,
not a production throughput guarantee.

Decision: keep read-ahead test-only. Evaluate a broader JPEG metadata/layout and
large-asset corpus, memory/response-time costs, and window/threshold choices
before proposing a production policy. No backend, chunk-size or default changes.

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
`Reader.fromBlob(client, format, asset, context, detachedManifest)` can also
validate caller-supplied detached manifest-store bytes; the argument is
optional, and embedded reads keep their existing behavior when it is omitted.

The experimental seventh argument to `Reader.fromBlob` supplies an opt-in remote
host, also available as the fifth argument to `client.reader.fromBlob`:

```ts
await Reader.fromBlob(client, "image/jpeg", asset, context, undefined, {
  allowedOrigins: ["https://manifests.example.com"],
  maxBytes: 4 * 1024 * 1024,
  timeoutMs: 5000,
  signal: abortController.signal,
});
```

JPEG standard XMP discovery runs in Rust; the session issues the remote request
only when no embedded/detached store takes precedence and these options enable
fetching. The JavaScript host checks exact origins before networking, omits
credentials/referrer, forbids redirects, enforces actual streamed response size,
and aborts fetch/body reads on timeout or caller cancellation. Failures reject
without legacy fallback. HTTP is allowed only for explicitly listed loopback
origins used in tests; other origins require HTTPS. An allowlist is caller
authorization, not an automatic guarantee that a destination is safe: approve
only trusted services. CORS still applies. Remote fetching is off by default.
Extended XMP and complex RDF structures are unsupported; malformed or ambiguous
standard XMP fails explicitly. The local-server M3 tests run in all three browser
engines, including cross-origin CORS denial/success and retry against a second
ephemeral loopback server. Tests do not contact a public service.

Disposal invalidates the runtime immediately. In-flight work drains and rejects
instead of publishing a handle/result; borrowed builders are freed only after
their pending operation finishes. Calling `free` is idempotent. The inline
loader shares one initialized module per realm, rejects a different resource
after initialization, and permits retry after failed initialization.

### Proof and remaining scope

The ten M1 cases prove actual artifact loading and failure recovery,
WebCrypto signing, trusted/no-anchor/tampered validation, bidirectional cross-read
against legacy-signed fixtures and the legacy reader, suspended read/build
interleaving, exactly-once claim-signing callbacks, host failures, unsupported
settings, missing timestamps, and disposal during pending work. Both engines'
clocks are frozen to 2026-09-01 inside the public test certificate's validity
window. The two M2 cases prove CBOR assertion values, separate CAWG trust
anchors, and rejection of unsupported trust verification. The public fixture private key in generated test data is test material
only and protects nothing; never use it to sign real credentials.

The upstream denominator is still **249 declarations**: five new-backend passes
require all three browsers; 244 remain unported. M1 records 45 executions
(15 selected cases per browser). M2 records six subset-proof executions without
inflating upstream parity.

Not yet supported: Worker hosting/configuration, full manifest/signature and
resource reporting, broad/global settings, remote manifests, online OCSP,
non-JPEG formats, full legacy builder/signer APIs, or published distribution.
Explicit Context inputs outside PEM signing/CAWG trust anchors, supported
trust verification, and OCSP settings reject rather than pretending to be honored. M1 proves
missing-service timestamp failure; a deterministic TSA success fixture remains
required when a browser transport is introduced.

See the [migration plan](../docs/js-migration-plan.md) for M2+ acceptance gates.
