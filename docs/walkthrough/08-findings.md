# 8. Findings

What building this taught us. Some are about the architecture; some are
about C2PA itself.

## The architecture mostly held

* **One engine under three async models worked.** The js-compat and
  node-compat tests compare against the synchronous host's output; the
  engine did not change to accommodate either binding.
* **Request *sets* are the right primitive.** The reader's hashing window
  (concurrent 64 KiB reads) maps directly onto Node overlapping `fs` reads
  and onto browser `Promise`s, with no engine-side concurrency machinery.
* **Time and randomness as requests/inputs make results reproducible.**
  A fixed "now" gives deterministic reads; the missing RNG is why
  `instance_id`/`label` are caller-supplied.
* **Plain-data boundaries pay off.** Plans, ranges and byte vectors let a
  handler be tested against a slice and let the file builder hash from a
  plan before anything is written.

## Surprises

* **A format's structure leaked into the contract.** One exclusion range
  was a JPEG-shaped assumption. TIFF exposed it, and only differential
  testing against c2pa-rs made it fail loudly ([formats](05-formats.md)).
* **Failure semantics differ by direction.** Reading is graceful (an
  unreachable OCSP responder is fail-open; one `Failed` reply doesn't
  doom the report). Writing is strict (any host failure is fatal — a
  wrongly bound manifest is worse than none).
* **Don't trust components you don't control.** `FileBuilderSession`
  re-checks a handler's plan itself; a foreign handler would need the same.
* **Revocation has sharp edges.** An authenticated OCSP response that does
  not affirmatively vouch is *revoked*, not inconclusive; a live
  responder's certificate must be valid *now*.
* **Sans-I/O makes the clock an explicit dependency** — and exposes how
  much of validation quietly assumed one.
* **Asset-supplied URLs are an SSRF surface** the moment a host answers
  `Ocsp`; the policy belongs with the host that owns the network.

## The sidecar experiment

Reproducing Gavin Peacock's `c2pa-sign-sample` as independent elements
taught a few things:

* **The seams are cheap when the interface is dumb.** An assertion crate's
  whole output is `EncodedAssertion` (label + CBOR); the claim holds
  `HashedUri`s. Adding an assertion type touches neither the session nor
  the claim.
* **A sub-session composes like a crate.** `DataHashSession` is driven
  inside `SidecarSession` by forwarding requests and replies — the same
  move `FileReadSession` makes. Request-ID mapping is the only cost.
* **`HashedUri` belonged in `primitives`.** It is shared by the claim,
  identity assertions and (later) ingredients, and carries one subtlety —
  hash the box *contents*, not its header — worth having once.
* **Doing the obvious thing with `jumbf` was wasteful.** Render-to-hash
  then render-again cost 2.3× `c2pa-store`'s time and 1.5× its peak on large
  payloads; rendering once and splicing brought it to ~1.5× time. The two
  JUMBF implementations emit identical bytes and parse each other's output
  ([comparison](../../c2pa-core-comparison/README.md)).
* **Entropy and the clock are inputs.** Gavin's ephemeral-cert code drew on
  `getrandom` and `now_utc()`; taking both as parameters made it sans-I/O,
  Wasm-clean and deterministic, so its output is testable.
* **A spec discrepancy surfaced.** The claim's `signature` must be an
  *absolute* URI; `contentauth-c2pa-builder` writes the relative form
  (readers, c2pa-rs's included, accept both). The new claim crate writes the
  absolute one.
* **Neither project honors the XMP instance-ID "should".** The claim's
  `instanceID` should be the asset's `xmpMM:InstanceID` when it has XMP.

## Things that were cheap *because* of the architecture

* A Wasm build with no `cfg` gymnastics in the engine.
* A Node binding with no threads or locks in Rust.
* Interleaving two reads on one thread.
* Swapping the format handler under a session (`AnyFormat`) with no
  changes below the host.

## Things that were *not* cheap

* Matching c2pa-rs's JSON/error contracts exactly (it's a moving target;
  the repo already tracked c2pa-rs 0.91's trust-anchor and revocation
  changes).
* Keeping a from-scratch validator aligned with the spec: ingredients,
  redaction and remote manifests are all still open.

**Next:** [Future directions →](09-future.md)
