# Porting security fixes from c2pa-rs to the state-machine SDK

This is the running record of an experiment: taking each security /
vulnerability fix landed in [c2pa-rs](https://github.com/contentauth/c2pa-rs)
and asking, for the from-scratch [state-machine SDK](../../README.md), three
questions in order:

1. **Is the exploit even applicable here?** The two SDKs share almost no code
   or API, so we reduce each vulnerability to its *exploit mechanism* — the
   attacker-controlled input and the unsafe operation it reaches — and look
   for that mechanism on any reachable path here, wherever it lives.
2. **If applicable, is it already handled?** This SDK was written later and
   often avoids a bug by construction; if so we cite the exact code.
3. **If applicable and unhandled, port the fix** idiomatically (errors through
   the crate's `Error` type, no `unwrap`/`expect`/`panic`) and add a
   regression test that fails before and passes after.

Every entry gets a one-word verdict plus, wherever we can, a regression test
that reproduces the original proof-of-concept against this SDK.

> **Scope note.** c2pa-rs PRs sometimes fix more than one format at once. Each
> page here covers only the part relevant to its format or workflow; the rest
> is handled on that part's own page.

## Verdict legend

| Verdict | Meaning |
|---|---|
| **Not applicable** | The exploit's unsafe operation has no reachable analogue here — usually because the architecture precludes it. No code change; a regression test is added where it can still demonstrate immunity. |
| **Already fixed** | The analogue exists and the current code already enforces the needed invariant. We cite the code and add/point to a regression test. |
| **Latent** | Not reachable *today* only because the feature it lives in isn't implemented yet. No fix now; the requirement is recorded against that feature's roadmap item so it isn't lost. |
| **Ported** | The analogue existed and was unguarded; we implemented the fix and added a regression test. |

## Why whole classes of exploit don't reach this SDK

Several recurring c2pa-rs vulnerability classes are neutralized here not by a
spot fix but by the architecture. Worth stating once, since it explains most
of the "Not applicable" verdicts:

- **Sans-I/O: the engine never allocates read buffers or performs I/O.** A
  parser asks its *host* for a byte range (`IoRequest::Read` over a
  `ByteRange`); the host owns every allocation and read. The classic
  `let mut buf = vec![0; attacker_len]; read_exact(&mut buf)` over-allocation
  simply has no home in the engine.
- **Every requested range is bounded against the real source length first.**
  The host answers a length query once, and a range that runs past it is
  refused with `checked_add(...) > source_len` *before* the read is issued.
  Forged length/offset/count fields become a refusal, not an allocation or an
  out-of-bounds read.
- **Readers are minimal locators, not full decoders.** A format reader extracts
  only the C2PA manifest store and ignores everything else, so most
  attacker-controlled structure (arbitrary tags, strips, tiles, private
  boxes) is never interpreted and never drives memory.
- **The clock, network, randomness and signing are host inputs, not ambient
  calls** — so time-of-check bugs, SSRF via asset-supplied URLs, and similar
  shift to a boundary the host controls explicitly.
- **Writers splice, they don't re-serialize.** Embedding copies the source
  bytes verbatim and appends the store ("nothing moves"); it never walks and
  re-emits the container's internal structures, so clone-time amplification
  has nothing to amplify.
- **Hard bindings are checked against the manifest's own signed exclusions**,
  never recomputed from the container's length fields — so a forged length
  can't widen an unhashed window.

None of this makes the SDK automatically safe; it narrows *where* a bug could
live. Each entry below still verifies the specific mechanism.

## Status by format and workflow

| Area | Page | Processed | Needs porting |
|---|---|---|---|
| TIFF / BigTIFF / DNG | [tiff.md](tiff.md) | 7 | 0 (1 latent, tracked) |
| JPEG | _not started_ | — | — |
| COSE / signature / trust | _not started_ | — | — |
| JUMBF / CBOR / claim parsing | _not started_ | — | — |
| OCSP / revocation / timestamps | _not started_ | — | — |
| CAWG identity | _not started_ | — | — |
| Ingredients / update manifests / redaction | _not started_ (feature not yet built — see [09-future.md](../walkthrough/09-future.md)) | — | — |

## Maintaining this record

- One row per c2pa-rs PR on the relevant format/workflow page, in a summary
  table, with a detailed section below it.
- When a PR touches several areas, add a row on each affected page covering
  only that area, and cross-link.
- A **Latent** verdict must leave a matching note on the roadmap item
  ([09-future.md](../walkthrough/09-future.md)) so the requirement travels
  with the feature.
- Prefer a regression test over prose: it is the proof the verdict is real,
  and it fails loudly if the SDK ever regresses.
