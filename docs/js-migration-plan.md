# c2pa-js migration: implementation and proof plan

Status: M0 and the defined M1 slice are implemented; M2 is partial and M3 is
in progress. Researched on 2026-10-12. The M0 browser oracle executes the legacy
SDK, not the state-machine bindings. This document does not claim a full-parity
shim already exists.

## Target and compatibility contract

Build a JS SDK on the sans-I/O state machines, with compatibility entry points
that let applications migrate without rewriting their reader/builder calls.
Cover browser and Node, reading and writing, public types and package exports,
observable errors, settings, resources, and lifecycle behavior.

Freeze the first oracle to upstream
[`contentauth/c2pa-js` commit `3c642db3e566f20ede9442090d1d414f424bcea1`][upstream].
At this revision `@contentauth/c2pa-web` reports version `0.15.3`.
Record the package versions, lockfile, SDK/Wasm artifacts, test inventory, and
fixture hashes together. Track newer upstream revisions separately rather than
changing the oracle underneath an implementation milestone.

Full parity means the pinned public contract passes on the new backend without
legacy-engine assistance. Passing a JPEG subset is a prototype milestone, not
full parity. Production suitability additionally needs corpus, robustness, and
performance evidence; SDK test parity alone does not establish those.

## Existing building blocks and gaps

- [WasmReader](../contentauth-c2pa-js-compat/src/web.rs) already exposes
  `fromBlob`, `activeLabel`, `manifestStore`, `activeManifest`, and `json`.
  It drives the same synchronous file session as the other hosts.
- [WasmBuilder](../contentauth-c2pa-js-compat-sign/src/web.rs) exposes
  `fromJson` and async `sign`, with a JS-owned signer and byte-array outputs.
- The [Node reader](../c2pa-node-compat-addon/index.mjs) and
  [Node builder](../c2pa-node-sign-addon/index.mjs) already put async work in JS
  around synchronous session functions. Reuse these drivers and error contracts.
- [Manifest reporting](../contentauth-c2pa-js-compat/src/manifest_store.rs)
  currently projects assertions as labels, not the complete assertion objects
  expected by c2pa-js. Richer reporting must originate in the reader's result,
  then flow through the shared projection and both bindings.
- [Context parsing](../contentauth-c2pa-js-compat/src/context.rs) recognizes only
  a settings subset. Compatibility requires the upstream JS Context resolution,
  casing, defaults, precedence, and trust-policy behavior, not merely passing an
  arbitrary settings object through JSON.
- Browser format selection currently accepts JPEG only. Browser OCSP is declined
  by `WebPlatform`; remote manifests, fragmented assets, and resource retrieval
  are documented gaps.
- Existing CI compiles the browser bindings for Wasm. It does not execute them in
  a browser. Native async tests are useful lower-layer proof, not a replacement
  for that gate.

The existing native baseline was run successfully during this planning work:

```sh
cargo test -p contentauth-c2pa-js-compat -p contentauth-c2pa-js-compat-sign
```

## Ownership and API shape

Keep three layers distinct:

1. **Engine and domain sessions:** synchronous Rust; no filesystem, fetch,
   browser objects, workers, or async runtime. Add missing domain capabilities
   here only when they genuinely belong to validation/building.
2. **Platform adapters:** browser Blob/clock/network/signer operations and Node
   range reads/writes/fetch. Container details remain in format handlers.
3. **JS API and compatibility facades:** factories, settings resolution,
   Promise shapes, errors, resource lifetimes, and old method names.

The new API should expose host control without forcing ordinary callers to
drive every request manually: a client for read/build operations, with explicit
host capabilities, and an advanced session adapter where needed. Reuse the
existing async browser host for the first vertical slice; do not first rewrite
it as a second JS orchestration loop. A later flattened browser session bridge
can reuse the Node request/reply model when custom JS hosts require it.

PROPOSED implementation locations:

- `c2pa-js-state-machine/`: a standalone TypeScript package containing the new
  client, web/Node compatibility entry points, and contract harness.
- `contentauth-c2pa-web-bindings/`: a thin browser `cdylib` packaging the existing
  read/sign implementations and generated JS glue into one SDK artifact.
  Verify generated exports rather than assuming an `rlib` or `cargo check`
  produces a loadable browser SDK.

Use Vite/Vitest with Playwright's browser provider, matching upstream's existing
runner rather than introducing a second browser test framework. Keep this
package's JS tooling isolated from the portable Cargo members. Pin the
wasm-bindgen CLI to the resolved library version. A new workspace member must
still pass the repository's Wasm/MSRV/lint checks.

## Compatibility shims and incremental migration

Provide separate web and Node compatibility entry points over the new client.
The browser facade must preserve `createC2pa`, static `Reader`/`Builder`
constructors, deprecated reader/builder factories, and the inline and Worker
entry points. The Node facade must preserve its synchronous definition-editing
methods alongside async reads/signing, signer adapters, and file/buffer shapes.
Use the pinned declarations and export inventory as the authoritative list.

Resolve the backend explicitly when creating a client/runtime. Start with
legacy as the migration default; callers opt into state-machine for a tested
workflow. Bind Reader/Builder handles immutably to that backend, context, and
runtime. Mixed-backend objects must be rejected rather than silently coerced.

The compatibility factory can inject either backend into the same tests and
application example. Keep resource URLs separate for each backend: an existing
c2pa-js `wasmSrc` cannot be treated as a state-machine Wasm binary. Preserve
`workerSrc`, precompiled-module loading, CSP behavior, and loader errors at the
compatibility boundary.

Preserve observable details, not just method names:

- `null` for a missing manifest, versus rejection for malformed/unsupported
  input; browser error strings versus Node Error names and messages.
- Promise versus synchronous return behavior, optional fields versus `null`,
  array ordering, byte-array/Buffer/Blob types, and cloned versus borrowed data.
- Global and per-call settings, independent Context instances, cached context
  resolution, and precedence in deprecated factories.
- `free`/`dispose`, post-disposal calls, Worker termination, and hidden
  Reader/Builder internals during enumeration/serialization.
- Public TypeScript assignability and package subpath/resource exports, not
  only successful runtime imports.

Do not catch a state-machine failure and retry on legacy automatically. In
particular, signing or writing must not run twice. An explicit capability
decision may select legacy *before* a workflow starts, but record that selection;
such a result never counts as state-machine parity. Unsupported features must
remain identifiable, not become plausible empty resources or manifest fields.

This requested compatibility boundary is intentional even though the internal
Rust prototype permits breaking changes. Preserve the JS migration contract
while updating internal callers normally; do not add engine-wide legacy shims.

## Implementation sequence and exit gates

### M0: freeze the contract and build a dual-backend harness

Implemented in [c2pa-js-state-machine](../c2pa-js-state-machine/README.md):
249 test declarations across 15 files, 33 exported source surfaces, source and
published-type fingerprints, and five unchanged legacy reader tests passing in
Chromium. Initially all 249 state-machine declarations were explicitly unported;
M1 now proves five while retaining the remaining 244 in the ledger.

Inventory public exports/declarations and every upstream test across web, Node,
types, and utilities. Include inline loading, Worker sanitization, settings,
signers, identity assertions, and Trustmark, not just reader tests.

Adapt upstream's [test fixture injection][test-fixtures] to supply legacy or
state-machine factories. Share fixtures, contexts, clock, and mock responses;
leave test bodies and expectations intact wherever possible. Isolate the
upstream oracle as a development dependency/build artifact, never as an
unadvertised runtime implementation of the new backend.

Maintain a machine-readable contract ledger with upstream revision, file/test
identity, fixture hashes, platform, milestone, backend, status, and blocker.
Statuses distinguish passing, failing, and not ported. A missing/filtered test
does not pass. Document unavoidable harness-only changes and retain upstream
MIT licensing and copyright notices for copied tests/assets.

**Exit:** the pinned legacy runner passes the selected original tests; every
upstream test is accounted for, and the new backend's initial failures are
visible. No xfail/skip count can disappear from the parity denominator.

### M1: a browser-executed JPEG read/sign vertical slice

Implemented in [the inline prototype](../c2pa-js-state-machine/README.md) and
[`contentauth-c2pa-web-bindings`](../contentauth-c2pa-web-bindings/README.md).
The five unchanged upstream cases and ten separate milestone cases run in
Chromium, Firefox, and WebKit (45 executions). Evidence fingerprints the actual
generated artifacts and inputs. The facade preserves the selected Reader
contracts; its baseline raw ES256 signer is intentionally not yet the legacy
COSE-producing signer API. Full reporting, Worker hosting, distribution, and
remaining builder/shim parity stay in later milestones. The frozen clock is
2026-09-01, inside the public signing fixture's validity window.

Build real Wasm and generated JS, load it through the proposed package, and run
on Chromium, Firefox, and WebKit. First prove direct/inline execution; establish
a Worker host for the compatibility default before claiming Worker parity.
Exercise packaged resources rather than mocking the Wasm module.

Implement only the facade behavior required by this slice: initialization,
format sniffing, reader lifecycle, byte conversion, precise error mapping, and
baseline signing. Use a checked-in test certificate/key through WebCrypto,
importing the private key as non-extractable; signing returns COSE-compatible
ES256 bytes. Freeze both backends' clocks inside the fixture validity window.

Required proof:

- The original web reader tests starting at lines 54, 64, 302, 408, and 420
  pass unchanged: unsigned asset, size rejection, error propagation, freeing,
  and non-enumerable internals. Their assertions remain the upstream oracle.
- A new baseline JPEG signs in the browser, reads back `Trusted` with the
  configured signing root, and exposes the generated asset/manifest byte types.
  A no-anchor read and a tampered-asset read demonstrate that trust/validation
  have not been replaced with a success-shaped projection.
- Read legacy-signed output through the new backend and new-signed output
  through legacy. Compare binding semantics and validation, not random ECDSA
  signature bytes. Label known full-reporting differences as M2 blockers.
- Two reads and two builds genuinely interleave across suspended host requests.
  Instrument requests/callbacks; verify no duplicate signing callbacks for a
  given signing purpose, and rejection does not poison the next operation.
- Signer failure, Blob failure, invalid definition, missing requested timestamp
  service, initialization failure, and disposal leave no unhandled rejection or
  live Worker/resource after teardown. Add timestamp success with a deterministic
  local TSA fixture when that service adapter is introduced.
- The existing Rust JS read/sign suites and portable CI checks remain green.

**Exit:** all mandatory M1 cases pass in all three browsers with zero skipped
mandatory cases. Publish a reproducible demo and a report explicitly calling
this a JPEG prototype, with the M2+ ledger still visible.

### M2: complete reader reporting, settings, and resources

Extend reader result producers before expanding the shared manifest projection.
Decode assertion values/kinds, ingredient relationships and validation results,
signature metadata, thumbnails/resources, and CAWG reporting. Resolve resources
to exact bytes through the same host/session boundary.

Implement upstream Context semantics, including separate signing/identity trust,
trust-disabled behavior, per-operation settings, and resolution caching.
Settings that cannot yet be honored must not silently behave like a supported
setting when the application explicitly selects the new migration facade.

**Exit:** the unchanged upstream full-store golden tests pass, including trust
enabled/disabled and independent Contexts. Resource tests compare complete byte
arrays. Node and browser agree on the shared report for the same asset/settings.
In particular, do not reduce upstream's `toEqual(ManifestStore)` tests to checking
only `validation_state` or assertion labels.

**In progress:** the reader now decodes CBOR assertion payloads and v2
created-assertion relationships. The inline facade accepts separate signing and
CAWG trust settings and rejects unsupported trust-verification settings.
Active-manifest validation-result buckets are projected and checked in Rust and
browser tests. Browser proof covers this subset; full-store equality, ingredients,
signature metadata, exact validation-result parity, thumbnails, and resource
bytes remain open.

### M3: network, formats, and runtime/distribution parity

Add remote-manifest and detached-manifest session capabilities, then host
transports; implement fragmented BMFF and the remaining upstream format matrix
through format handlers. JPEG, DASH/BMFF, and JXL fixtures already appear in the
upstream browser tests; derive the complete matrix from the pinned SDK instead
of assuming those three are exhaustive.

Provide controlled browser OCSP/remote fetch behavior with URL policy,
response limits, cancellation/timeouts, and deterministic local test servers.
Test failure, denial, CORS, and retry paths; do not rely on a public responder.
Keep HTTP outside the domain engine.

**In progress:** `FileReadSession` accepts detached manifest-store bytes and
surfaces a format-reported remote URL when `fetch_remote_manifests` is enabled.
The async compatibility host forwards that request through
`Platform::remote_manifest`; hosts without transport fail explicitly. The
inline JS reader now accepts detached manifest-store bytes and passes them
through the Wasm binding into that same session. The JS builder now also has an
explicit detached-output path: it skips placeholder reservation and encodes an
empty exclusion list so the hard binding covers the complete asset. Browser
proof strips the fixture's C2PA APP11 segment, verifies the output asset is
unchanged and has no active embedded manifest, then reads the detached store as
`Trusted`; a changed asset reports `Invalid`, and malformed detached bytes are
rejected. URL policy and bounded browser transport, remote-pointer parsing,
fragmented BMFF, and Worker/runtime parity remain open.

Prove Worker and inline paths, CSP-compatible `workerSrc`, module/URL loading,
package exports, cleanup, and invalid-handle behavior. Add test-only host counters
and interleaving traces; measure large-asset memory and event-loop stalls against
the pinned legacy backend. Record measurements before choosing regression
budgets; do not invent a performance threshold without a baseline.

**Exit:** upstream reader/inline/serialization tests pass on both runtime paths,
and supported formats, resources, detached and remote manifests are accounted
for without legacy fallback.

### M4: builder and Node surface parity

Expand beyond baseline signing: default definitions and ID generation at the
host, JSON/CBOR assertions, actions and transformations, archives, ingredients,
redactions, resources, external/detached output, CAWG credential-holder callbacks,
and all pinned signer/identity/Trustmark interfaces.

Definition-editing callbacks must preserve metadata/order and be atomic on
exceptions. For Node keep upstream synchronous editing behavior; browser
methods retain their Promise/Worker semantics. Preserve atomic output replacement
and streaming in the existing Node/file-builder implementation.

**Exit:** complete web and Node builder suites pass unchanged against the new
backend, and outputs validate in both readers. Run the exact same application
sources against both compatibility entries, with TypeScript compilation as well
as runtime tests.

### M5: full parity and opt-in rollout

Require every ledger case to pass for its applicable platform, including
utilities/types/package contracts; every accepted deviation remains a blocker
to an unqualified full-parity claim. Test the distributed tarball, not only source
aliases. Add differential corpus runs and then track upstream changes as new
ledger entries before updating the pinned oracle.

Only then consider changing the default backend. No removal of legacy entry
points is part of this plan.

## Concrete upstream test mapping

Line numbers below identify original test starts at the pinned revision.
M1 uses a small explicit gate; all other cases remain required for full parity.

| Upstream source | Cases / behavior | Gate |
| --- | --- | --- |
| [Web reader][web-reader] | 54 unsigned/null; 64 asset limit; 302 errors; 408 free; 420 private fields | M1 |
| [Web reader][web-reader] | 40 complete report; 77 format sniffing with original report; 91/124/164 Context handling; 253 resource bytes; 280 active manifest; 313/339/362 complete trust goldens | M2 |
| [Web reader][web-reader] | 185/205 fragmented BMFF; 221/235 fragment limits; 385 remote manifest | M3 |
| [Web reader][web-reader] | 436/448/467 deprecated factories and settings precedence | M2/M3 |
| [Inline][inline] and [sanitization][sanitize] | inline smoke; nullish stores, null-prototype maps, `__proto__` labels and siblings | M3 |
| [Web builder][web-builder] | 29/133 definitions; 185/217/263 archive round trips; 336 actions; 373/411 redactions; 466+ ingredients | M4 |
| [Web builder][web-builder] | 577/615/684 filtering; 698/727/755/768/790 assertion edits; 841+ action transforms; 1206/1232 ingredient callbacks | M4 |
| [Web builder][web-builder] | 1250 JXL signing; 1286 CAWG signer payload; 1354 reservation failure/recovery; 1400+ factories/settings | M4 |
| [Node reader][node-reader] | 122/135 buffers; 145/155 files/sniffing; 167/174 unsigned/limit; 184/198/212/245 detached/context; 278 output; 296/305 embedded flag; 316 CAWG | M2-M4 |
| [Node builder][node-builder] and remaining SDK suites | assertions, ingredients, redactions, external signing, atomic transforms, signer/settings/identity/Trustmark contracts | M4/M5 |

Use upstream's complete expected objects and byte fixtures. Do not replace
them with snapshots generated by the new implementation.

## Comparison rules and proposed commands

For reads, compare the full public result, including absent fields, ordered
arrays, validation codes/URLs, errors, resources, and identity outcomes.
Only ignore JSON object key order. Freeze time/network inputs; do not broadly
strip validation failures, unknown fields, timestamps, or status explanations.

For signing, compare definition semantics and expected decoded results with
per-test, explicit handling of generated IDs and signatures. Never claim
byte-identical signed assets with randomized ECDSA. Both outputs must validate
their own hard binding and signature through both readers; preserve all caller
supplied metadata. Separate algorithm capability gaps from wrapper bugs.

The M0 commands now exist:

```sh
npm --prefix c2pa-js-state-machine run prepare:upstream
npm --prefix c2pa-js-state-machine run inventory:check
npm --prefix c2pa-js-state-machine run typecheck
npm --prefix c2pa-js-state-machine test
npm --prefix c2pa-js-state-machine run test:oracle
npm --prefix c2pa-js-state-machine run report:parity
# Intentionally fails while the new backend is unported.
npm --prefix c2pa-js-state-machine run check:parity
```

The following remain **PROPOSED M1+ scripts**, not current commands:

```sh
npm --prefix c2pa-js-state-machine run build:wasm
npm --prefix c2pa-js-state-machine run typecheck:compat
npm --prefix c2pa-js-state-machine run test:browser:m1
npm --prefix c2pa-js-state-machine run test:browser:parity
npm --prefix c2pa-js-state-machine run test:node:parity
npm --prefix c2pa-js-state-machine run test:package
```

The M1 script runs all mandatory cases on Chromium/Firefox/WebKit. The full
parity commands fail for an unported, missing, skipped, or failing required case;
the report includes the pinned revision and pass/fail/unported denominators.
Publish JUnit output, the ledger, structural diffs, browser traces on failure,
and build/fixture hashes in CI. Keep oracle and new-backend results distinct.

Add a separate browser-runtime CI job beside the existing Wasm compilation and
Node addon jobs. Install browser binaries there and serve fixtures locally.
Existing Cargo validation remains separate; browser runtime success does not
replace Wasm portability, lint, MSRV, or format/conformance checks.

## Rollout and rollback proof

1. Keep legacy packages usable while applications select the new compatibility
   entry for one tested workflow at a time.
2. Offer the new host-aware client independently; switching APIs and switching
   engines need not happen in the same application change.
3. Test mixed legacy/new clients in one process, with independent contexts,
   workers, resource loaders, and output destinations. Do not share live handles.
4. Rollback selects the legacy factory for newly created clients, using the
   legacy resources/settings. Explicitly dispose/drain old clients; do not try
   to serialize or resume an in-flight Wasm session on the other backend.
5. Preserve already-signed assets and archive interoperability. Rollback tests
   read new-produced assets with legacy and confirm that a failed sign leaves
   an existing output unchanged and does not repeat signer/network side effects.

M0 establishes the frozen contract and passing legacy oracle. Completion of
the next implementation milestone means M1 runs and passes against the actual
state-machine browser bindings; that execution is not claimed yet.

[upstream]: https://github.com/contentauth/c2pa-js/tree/3c642db3e566f20ede9442090d1d414f424bcea1
[test-fixtures]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/test/methods.ts
[web-reader]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/lib/reader.spec.ts
[web-builder]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/lib/builder.spec.ts
[inline]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/inline.spec.ts
[sanitize]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-web/src/lib/worker/sanitizeManifestStore.spec.ts
[node-reader]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-node/js-src/Reader.spec.ts
[node-builder]: https://github.com/contentauth/c2pa-js/blob/3c642db3e566f20ede9442090d1d414f424bcea1/packages/c2pa-node/js-src/Builder.spec.ts
