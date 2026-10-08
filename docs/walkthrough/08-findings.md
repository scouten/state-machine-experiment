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

* **The plan makes one pass possible.** The old shape wrote the output and
  then read it back to hash it. Because an `EmbedPlan` describes the whole
  output up front, the hash can be folded in as each piece is produced
  (RIFF: the only manifest-dependent byte outside the new chunk is a size
  field computed from the store's length). Measured against Gavin
  Peacock's `asset-io` (`asset-io-comparison/`), the one-pass build runs
  at the speed of a bare read-hash-write loop — a few percent *ahead* of
  `asset-io`'s own `write_with_processing` — while the read-back shape
  costs about 20% more. The first version was slower than the read-back
  one, for an unexpected reason: the host loop cloned every outstanding
  request, copying each 1 MiB `Write` payload once more, which cost about
  half again as much time until it answered requests while borrowing them.
* **A data-only exclusion is not what c2pa-rs wants for RIFF.** asset-io
  hashes the `C2PA` chunk's header and excludes data plus pad; c2pa-rs
  excludes header plus data. Only the real validator could say.

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
