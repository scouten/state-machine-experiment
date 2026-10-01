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

Minimum supported Rust version: 1.88.0.

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
