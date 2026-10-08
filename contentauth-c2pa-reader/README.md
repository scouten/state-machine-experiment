# contentauth-c2pa-reader

An experimental, fully-synchronous, sans-I/O crate for reading and
validating C2PA manifest stores, built on
[`contentauth-state-machine`](../contentauth-state-machine).

This is a personal prototype exploring an alternative architecture for the
[c2pa-rs] SDK: a reader that implements C2PA manifest reading and
validation as pure synchronous computation, communicating with its host
through a state machine that is handed back and forth. All
potentially-asynchronous operations — file I/O, container format parsing,
network access — are externalized to the host application, which can
implement them with whatever async machinery is natural in its own
language and runtime.

This crate carries no engine logic of its own: request tracking, session
lifecycle bookkeeping, and protocol-level errors all come from
`contentauth-state-machine`. [`ReadSession`] implements that crate's
`Session` trait, adding only the read/validate workflow and its own
request vocabulary. See the sibling crate's
[README](../contentauth-state-machine/README.md) for the interaction
contract and the `advance` / `outstanding_requests` / `fulfill` / `finish`
cycle itself.

## What `ReadSession` validates today

[`ReadSession`] reads a manifest store end to end (JUMBF parsing, claim
decoding, report population) and verifies:

* **Integrity** — each assertion's hash against the value the claim
  records, and the active manifest's hard binding against the asset
  itself, hashed in-crate from chunks the host streams in.
* **The claim signature** — checked in-crate against the signer's
  certificate.
* **Trust** — the signer's certificate path is built and verified against
  configured trust anchors, held to the C2PA certificate profile. An RFC
  3161 timestamp in the claim signature is validated and can rescue a
  since-expired certificate: a manifest signed years ago with a
  since-expired certificate still reads as valid when a *trusted*
  authority stamped it at the time.
* **Revocation** — per the C2PA specification's own §15.9 process: OCSP
  only (CRLs are outside its vocabulary), checking a stapled response in
  the manifest first, then an online query (on by default —
  `ReadSettings::check_ocsp`) when nothing there settled it. A responder
  that cannot be reached at all is fail-open and never held against the
  manifest, but a response that *is* received and authenticated, yet does
  not affirmatively vouch for the certificate, reads as revoked rather
  than merely inconclusive — see [`src/ocsp.rs`](src/ocsp.rs)'s own module
  docs. CA certificates above the signer are checked the same way (stapled
  response, else their own AIA responder), but are reported only if
  revoked, as `signingCredential.untrusted`. A live response's responder
  certificate must be valid *now*, not merely when the response says it
  was produced.

* **Claim structure, for both claim versions** — a `c2pa.claim` (v1) and a
  `c2pa.claim.v2` decode into the same `Claim`: a v2
  `claim_generator_info` is a single map (with `specVersion` and `icon`),
  a v1 one an array, and v2's `redacted_assertions` are read too. A v2
  claim missing a field the specification requires (`instanceID`,
  `signature`, `created_assertions`, `claim_generator_info` and its
  `name`) is reported `claim.malformed`, and one that redacts an assertion
  in its *own* manifest `assertion.selfRedacted`. Not yet done for
  `redacted_assertions`: checking that an ingredient's redacted assertion
  was actually zeroed (`assertion.notRedacted`), which needs ingredient
  manifests.

* **CAWG identity assertions** — `cawg.identity` (and `cawg.identity__N`)
  assertions are decoded into `Manifest::identity_assertions` and
  verified: the assertion's structure and zeroed padding; that each
  assertion it vouches for is in the claim, with the claim's hash, and
  that a hard binding is among them and nothing is named twice; and then
  the credential itself, dispatched on `sig_type` in
  [`src/identity/mod.rs`](src/identity/mod.rs). Today that is
  **`cawg.x509.cose`** — a detached-payload `COSE_Sign1` over the
  `signer_payload` exactly as encoded (found by byte span, never decoded
  and re-encoded), whose certificate chain is judged like a claim
  signer's but against its own anchors,
  `ReadSettings::identity_trust_anchors` / `identity_trust_lists` (CAWG
  publishes its trust list separately from C2PA's), with CAWG's own
  `cawg.identity.*` and `cawg.x509.*` status codes. Revocation is not
  checked: CAWG's vocabulary has no codes for it. `cawg.identity_claims_aggregation`
  is recognised and reported `cawg.identity.sig_type.unsupported` (this
  crate's own code, informational) — it needs the network to resolve a
  DID, and will bring request variants of its own; any other `sig_type`
  is `cawg.identity.sig_type.unknown`. **Failures here are scoped to the
  one assertion**: they are failures (`ValidationStatus::is_failure`) but
  never lower the store's `ValidationState`
  (`ValidationStatus::affects_validation_state`), which is how c2pa-rs
  treats them too. Not yet done: `expected_*` fields of the
  `signer_payload`, which a signer may add to constrain the claim.

A report can reach `Trusted` or `Valid`. Not yet checked, and able to
change a verdict: ingredient manifests and remote manifest retrieval.

See [`src/read.rs`](src/read.rs) for `ReadSession` itself, and
[`src/validation.rs`](src/validation.rs) for the validation status
vocabulary and the checks that produce it.

## Request vocabulary

Defined in [`src/request.rs`](src/request.rs). Any request may be answered
with `ReadHostReply::Failed`.

| Request | Answered with | Purpose |
|---|---|---|
| `ManifestStore { stream }` | manifest store bytes or "none" | Host locates and extracts the JUMBF manifest store from the container. |
| `AssetBytes { stream, range }` | bytes | Streams asset bytes into this crate's internal hashing, for hard-binding verification. |
| `AssetLength { stream }` | total length in bytes | Needed to work out which asset ranges the hard binding covers, since it names only what to *exclude*. |
| `CurrentDateTime` | Unix timestamp | Certificate validity windows; this crate reads no clock. |
| `Ocsp { url, request_der }` | OCSP response bytes | A DER-encoded `OCSPRequest` this crate built; the host's job is only the HTTP POST (`Content-Type: application/ocsp-request`) to `url`, reporting back whatever bytes came back. `ReadHostReply::Failed` is fail-open, not fatal — see `ReadSettings::check_ocsp`. |

`ReadSettings::fetch_remote_manifests` documents a future
`HttpFetch`-style request for remote manifest retrieval that `ReadSession`
does not yet issue — this crate's request vocabulary has no such variant
today, since nothing constructs one.

## Building

```sh
cargo test
```

Minimum supported Rust version: 1.96.0.

Code format uses nightly rustfmt:

```sh
rustup toolchain add nightly
cargo +nightly fmt
```

## License

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.

[c2pa-rs]: https://github.com/contentauth/c2pa-rs
[`ReadSession`]: src/read.rs
