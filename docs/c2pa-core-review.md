# Review: `c2pa-core` (Gavin's second experiment)

**Status:** proposal for discussion between Eric and Gavin; companion to
[`asset-io-merge-plan.md`](asset-io-merge-plan.md).

**Basis:** a read-through of
[`gpeacock/c2pa-core`](https://github.com/gpeacock/c2pa-core) at commit
`8f3e630` (one commit, three crates, ~5.4k lines, all `0.0.0`/unpublished).
Unlike for asset-io, I also ran its tests: `cargo test` passes across the
workspace (about 70 tests, including a `c2pa-sign-sample` sign-and-verify
test). I did not run its fuzz target (needs nightly + `cargo-fuzz`), did not
verify its `no_std` claim (the `thumbv7em-none-eabi` target isn't installed
here), and did not check its output against c2patool or c2pa-rs.

## 1. What it is

A greenfield rethink of the **bottom of the stack** — the codecs beneath
anything like our reader and builder — as three small crates:

| Crate | Job | Notes |
|---|---|---|
| `c2pa-store` | Structural, zero-copy, `no_std`+`alloc` JUMBF parser for manifest stores; with feature `write`, a streaming box emitter and `ManifestStoreBuilder` | `forbid(unsafe_code)`; denies `unwrap`, `expect`, `panic`, **`indexing_slicing`** and **`arithmetic_side_effects`** in library code; a configurable `Limits` (depth, boxes per superbox, total boxes, input length); one cargo-fuzz target |
| `c2pa-claim` | v2 `Claim`, `HashedUri` (with `verify` against a parsed store), `DataHash`, `Actions`, `GeneratorInfo`, via `serde` + `c2pa_cbor` | std only for streaming-hash helpers |
| `c2pa-sign-sample` | Signs a file into a **sidecar** `.c2pa`: whole-file data hash, a `created` action, a v2 claim, Ed25519 `COSE_Sign1` with a throwaway CA | Sample/demo, not a library |

Its [`PRINCIPLES.md`](https://github.com/gpeacock/c2pa-core/blob/main/c2pa-claim/PRINCIPLES.md)
ranks seven priorities: (1) spec conformance, (2) attack/crash resistance,
(3) modularity, (4) speed/memory on huge assets, (5) zero-copy, (6) `no_std`
as a nice-to-have, (7) simple documented code. It is candid about gaps
(`c2pa_cbor` decoding allocates, no fuzz harness for the other two crates).

What it deliberately does not have: any I/O, any container format, signature
verification, certificate/trust handling, timestamps, revocation, v1 claims,
ingredients, or a hard binding for an *embedded* manifest.

## 2. How it relates to this workspace

It is not a competitor to asset-io's territory (formats) so much as to a
slice of **ours**: the JUMBF parse/emit and claim/assertion codecs that sit
under `contentauth-c2pa-reader` and `-builder`. Concretely:

| Concern | This workspace today | `c2pa-core` |
|---|---|---|
| JUMBF parse | External `jumbf` crate (already zero-copy); `MAX_BOX_DEPTH = 16` constant in `manifest_store.rs` | `c2pa-store` (own parser, `no_std`, `Limits` struct, depth 32) |
| JUMBF emit | `jumbf::builder` in `builder/src/jumbf.rs`, whole store built in one `Vec`, patched twice | `BoxWriter` over `Sink`/`SeekSink`; streaming; backpatches sizes |
| Claim decode | Walks `c2pa_cbor::Value` **by hand** (`claim.rs`, ~960 lines) so the understood fields stay explicit; v1 **and** v2 | `serde` derive, v2 only; unknown keys silently dropped |
| Hashed-URI check | `validation.rs`, hashes the assertion superbox payload | `HashedUri::verify`; same convention |
| Hard binding | `c2pa.hash.data` with exclusions and size-matched padding, via placeholder | `DataHash` with exclusions always `None`, padding always empty — sidecar only |
| Signing | Host signs (`Sign` request); COSE assembled in `cose.rs` | Ed25519 done inline in the sample using `c2pa_cbor`'s COSE module |
| I/O model | Sans-I/O sessions | None at all — pure functions over slices |

That last row is the important one. **A crate with no I/O and no hidden
state is exactly what a sans-I/O engine wants beneath it.** `c2pa-core`'s
layering (codec crates below, protocol above) is the layering this workspace
already has; the two are compatible, and the question is only which pieces
earn a place in the merge.

## 3. What is worth taking

1. **`Limits` as a type, not a constant.** Ours is one hard-coded depth (and
   our over-deep boxes are "left unparsed as opaque", a quiet failure mode).
   A caller-supplied `Limits` — depth, fan-out, total box budget, input size
   — that flows from `ReadSettings` down to the parser fits our settings
   model and bounds allocation, which is the property the fuzzing plan in
   the asset-io document wants to check. Take the shape; reconcile the
   default depth (his 32 vs our 16) against real manifests.
2. **Stricter lints.** `indexing_slicing` and `arithmetic_side_effects` on
   top of our `unwrap`/`expect`/`panic` denials. Cheap to try on the engine
   and handler crates; the fallout is a list of every place a length from
   untrusted bytes is used in arithmetic or indexing — the same places a
   fuzzer would find. Likely worth adopting for the format handlers first
   (JPEG, TIFF, and everything ported from asset-io).
3. **`verify_label_consistency`.** An opt-in check that a box's reserved
   label (`c2pa`, `c2pa.claim*`, `c2pa.assertions`, `c2pa.signature`) agrees
   with its content-type UUID, as a defense against a box masquerading as
   another. I did not check whether our reader does this (it classifies by
   UUID); if not, it is a small, spec-flavoured hardening item and a good
   validation status.
4. **Streaming assertion writes with inline hashing.** `ManifestStoreBuilder`
   hashes each assertion as it is written, and
   `begin_embedded_file_assertion` returns an **owned, movable**
   `EmbeddedFileAssertionWriter` fed with `write_chunk` — he documents it as
   suited to "a state machine … paused and resumed across suspension
   points". That is our model arriving from the other side. Today our
   `Assertion` carries its CBOR as a `Vec<u8>` in memory, so a large
   thumbnail or an embedded ingredient must be fully buffered; this is the
   missing piece for ingredients with big resources. In a session it becomes
   a request/reply loop: the builder asks the host for the next chunk of a
   resource, hashes it, and forwards it to the output. Note the constraint he
   found: the content box's header (which encodes its length) is hashed
   *before* the data, so the length must be known up front.
5. **A ranked priorities document.** `PRINCIPLES.md` gives a reviewer
   something to judge a change against, and records its own status. This
   workspace has the equivalent scattered through `CLAUDE.md` and crate
   READMEs. A short shared version, which Gavin and I can both sign up to,
   would reduce friction in the merge itself; the priorities in §5 below are
   a draft.
6. **`no_std` as a discipline, not a goal.** He keeps `c2pa-store` honestly
   `no_std` and avoids `std::io` in public signatures (`&[u8]` instead of
   `Read`). Our workspace needs Wasm, not `no_std`, so I would not require
   it, but "no `std::io` in public APIs below the host" is the same instinct
   as sans-I/O and is worth stating as a rule.

## 4. Concerns and gaps

- **Doc inaccuracy.** `c2pa-claim` describes `c2pa.hash.data` as being for a
  sidecar or remote manifest, "rather than one embedded in the asset (which
  would instead use a format-specific hard binding like a BMFF hash)". As
  far as I can tell from the spec snapshot this workspace carries, that is
  wrong for the common case: JPEG and PNG embedded manifests *do* use
  `c2pa.hash.data`, with exclusion ranges and a padded placeholder (what our
  builder does). The code is internally consistent — `exclusions` and `pad`
  are present but unused — so this is a documentation error with a real
  consequence: nothing yet exercises the embedded path, which is where the
  hard part of signing lives. Worth correcting, and worth confirming the
  claim against the spec text.
- **`serde` derive vs explicit decoding.** This workspace decodes claims by
  hand specifically so the set of fields understood is explicit
  (`CLAUDE.md`). `c2pa-claim` takes the opposite trade: concise and
  wire-compatible, but unknown keys are dropped on decode, so a decoded
  `Claim` can't be re-encoded and re-hashed — he documents "hash the original
  bytes" for exactly that reason. Validation in the reader needs the original
  bytes anyway, so this is workable, but it means `Claim` is a *builder*
  type here, not a faithful model of what was read. The two styles shouldn't
  be mixed in one crate; pick one for the merged claim code (I would keep
  ours for reading, and consider his derive for the write side only).
- **Fixed algorithm.** `ManifestStoreBuilder` hashes assertions with SHA-256
  only (`ALG = "sha256"`, flagged as future work). The reader and builder
  here support the registry's SHA-2 set; a merge must lift this.
- **Duplicate JUMBF parsers.** `c2pa-store`'s parser and the `jumbf` crate
  we use do the same job. Two options: adopt `c2pa-store` and drop the
  external dependency (we gain `Limits`, the lints, `no_std`, and one fewer
  upstream; we take on conformance ownership), or keep `jumbf` and port only
  `Limits`/lints/consistency checks. I lean to the former *only if* a
  differential test shows the two parsers agree on a real corpus and a
  malformed-input corpus; that test is the same differential-fuzzing idea as
  in the asset-io plan, applied to a smaller target.
- **Internal tension in the principles.** Priority 3 says `c2pa-store`
  "only understands box structure (no CBOR, no hashing, no signing)", yet
  its `write` feature depends on `sha2` and hashes inline — he explains why
  (a later assertion embeds an earlier one's hash), and I think the design is
  right, but the doc should say "hashing in the write path" rather than
  "no hashing". Similarly `c2pa-claim` takes `c2pa_store::ManifestStore` in
  `HashedUri::verify`, tying claim semantics to the store type; fine, but it
  is a coupling worth being explicit about.
- **Dependency alignment.** `c2pa-claim` uses `c2pa_cbor 0.78.0`; the sign
  sample uses a git branch (`gpeacock/cose-support`) for COSE; this
  workspace pins `0.77.4`. Any merge needs one CBOR version and a decision
  about whether COSE signing is assembled by `c2pa_cbor` or our `cose.rs`.
  Edition (2024 in the sample vs 2021 here) and MSRV (1.81/1.85 vs 1.88)
  also differ, harmlessly.
- **Zero-copy stops at CBOR.** `c2pa-store` is genuinely zero-copy, but
  `c2pa_cbor` decodes into owned `String`/`Vec<u8>`; both projects hit this
  wall, and our by-hand `Value` walk doesn't avoid it. A zero-copy decode
  mode upstream in `c2pa-cbor` would benefit both and is probably the
  highest-leverage single change for priority 5.
- **Fuzzing is a scaffold.** One target (`parse`) for the store; none for
  claim or CBOR; no corpus, no CI job, no recorded findings — the same state
  as asset-io's, and by his own account. The `parse` target does walk every
  accessor, which is the right habit.
- **Sample code uses `expect` freely** (fine for a demo, but it is the one
  place the workspace's own `unwrap`/`expect` policy doesn't apply, and
  shouldn't be copied into library code).
- **Not independently validated.** The sign sample prints a c2patool command
  but I did not run it, so "real C2PA manifest" is Gavin's claim until
  checked, ideally by the c2pa-rs differential harness we already have
  (`c2pa-rs-compat-conformance`).

## 5. Suggested shared priorities

If the three efforts are to be judged against one list, a combination of
`PRINCIPLES.md` and this workspace's rules reads roughly:

1. **Spec conformance** — wire behaviour matches the spec and c2pa-rs where
   they agree; differential tests are the evidence.
2. **Attack/crash resistance** — no panics, bounded allocation and
   recursion, fuzzed; strict lints in library code.
3. **Host-agnostic core** — no I/O, threads or clocks below the host;
   no `std::io` in public signatures of the engine, codecs or handlers.
4. **Modularity** — one job per crate; seams named in `Cargo.toml`.
5. **Throughput and memory on huge assets** — streaming, parallel-capable
   (see the asset-io plan), measured rather than asserted.
6. **Zero-copy where it can be** — borrowed views; shared-bytes replies.
7. **Simple, documented code.**

`no_std` stays "don't foreclose it", as in `PRINCIPLES.md`.

## 6. Where it fits in the plan

`c2pa-core` should become a **contributor to step 2 and step 3** of the
[asset-io merge plan](asset-io-merge-plan.md#5-plan-of-action) rather than a
separate track:

1. **With the fuzzing work (plan step 2):** take `Limits`, the stricter
   lints, and the fuzz harness style; add `c2pa-store` as a second parser in
   the differential fuzzer, against the `jumbf` crate, on valid stores and
   mutations.
2. **With the contract work (plan step 3):** design the chunked-resource
   assertion writer (§3.4) as a session request pair so ingredients with
   large resources stream; decide the claim-decoding style (§4); fix the
   digest algorithm in the builder.
3. **Decide the JUMBF parser.** After the differential test, either adopt
   `c2pa-store` as the engine's JUMBF layer or port its hardening onto
   `jumbf`. This is cheap to reverse and should not block anything else.
4. **Exercise the embedded path** in his sample: sign a JPEG through our
   `data hash`-with-exclusions builder using his streaming box writer, as a
   joint proof that the three efforts compose.

## 7. Questions for Gavin

1. Is `c2pa-core` meant to replace the `jumbf` crate and c2pa-rs's lower
   layers, or to sit beside them? Who is the intended consumer?
2. Was "`c2pa.hash.data` is for sidecars" a deliberate scoping decision for
   the first pass, or a misreading? Embedded hard bindings seem to be the
   natural next step.
3. How do you see `c2pa-store`'s `BoxWriter`/`Sink` relating to asset-io's
   `ProcessingWriter`? They solve the same "write while hashing" problem
   from opposite ends.
4. What did you find fuzzing `c2pa-store`, and what corpus did you use?
5. Is a zero-copy decode mode in `c2pa-cbor` something you intend to build,
   and would a joint priority list (§5) be acceptable?
