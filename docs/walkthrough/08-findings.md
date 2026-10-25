# 8. Findings

What building this taught us. Some are about the architecture; some are
about C2PA itself.

## The architecture mostly held

* **One engine under three async models worked.** The js-compat and
  session-bridge tests compare against the synchronous host's output; the
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

## Things that were cheap *because* of the architecture

* A Wasm build with no `cfg` gymnastics in the engine.
* A Node binding with no threads or locks in Rust.
* Interleaving two reads on one thread.
* Swapping the format handler under a session (`AnyFormat`) with no
  changes below the host.
* Deterministic record and replay: a session's only inputs are replies,
  so recording the host conversation (`Recorder`) captures everything a
  failure depends on, and `replay` reproduces it without the asset's
  original host, clock or network.
* Zero-copy payloads. Carrying asset chunks, manifest stores and writes as
  reference-counted `Bytes` instead of `Vec<u8>` changed no contract — only
  payload types — and, on a 16 MiB JPEG, cut a host that holds the asset
  in memory from 17 MB allocated per read to 0.11 MB, and `build_and_sign`
  from 51 MB to 34 MB. Most of the latter was invisible: the host loop's
  `outstanding_requests().to_vec()` (needed to release the session's
  borrow before `fulfill`) had been deep-copying every write.
  The saving stops at an FFI boundary: the C ABI still copies bytes in
  and out (see `contentauth-c2pa-c-api`'s README).

## Things that were *not* cheap

* Hand-writing each workflow's state machine: every point where a session
  waits on its host cost an enum variant carrying every live local, a
  handler, and the same `None` / `Failed` / wrong-reply arms again. The
  builder now writes its workflow as an `async fn` over the engine's
  `CoroutineWorkflow` instead — same host contract, same request vocabulary, every
  existing test and binding unchanged — and the compiler generates that
  state machine. The duplicated arms, and the coverage gaps they left,
  collapsed into one helper; `HashStream`'s chunk table and reorder buffer
  became a window of polled replies and shared buffers. The whole window
  must still be polled: a failed or wrongly sized later read must fail
  promptly even when an earlier read is outstanding. `Host::set_phase`
  retains diagnostic stage names without recreating the phase enum.
  Reply wakers are still necessary for wake-driven collections, but only
  `advance` polls the workflow. Terminal transitions cancel remaining
  requests and release stored replies and wakers rather than leaving
  work visible that the workflow can no longer consume.
* Matching c2pa-rs's JSON/error contracts exactly (it's a moving target;
  the repo already tracked c2pa-rs 0.91's trust-anchor and revocation
  changes).
* Keeping a from-scratch validator aligned with the spec: ingredients,
  redaction and remote manifests are all still open.

**Next:** [Future directions →](09-future.md)
