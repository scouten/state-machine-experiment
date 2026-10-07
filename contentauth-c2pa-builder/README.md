# contentauth-c2pa-builder

An experimental, fully-synchronous, sans-I/O crate for generating and
signing C2PA manifest stores, built on
[`contentauth-state-machine`](../contentauth-state-machine).

This is a personal prototype exploring an alternative architecture for the
[c2pa-rs] SDK: a builder that implements C2PA manifest generation and
signing as pure synchronous computation, communicating with its host
through a state machine that is handed back and forth — the write-side
counterpart to [`contentauth-c2pa-reader`](../contentauth-c2pa-reader). All
potentially-asynchronous operations — embedding bytes into a container
format, signing, RFC 3161 timestamping, network access — are externalized
to the host application.

This crate carries no engine logic of its own: request tracking, session
lifecycle bookkeeping, and protocol-level errors all come from
`contentauth-state-machine`. [`BuilderSession`] implements that crate's
`Session` trait, adding only the build/sign workflow and its own request
vocabulary. See the sibling crate's
[README](../contentauth-state-machine/README.md) for the interaction
contract and the `advance` / `outstanding_requests` / `fulfill` / `finish`
cycle itself. [`contentauth-c2pa-primitives`](../contentauth-c2pa-primitives)
holds the handful of types and encoders genuinely shared with the reader
crate — see that crate's README for what and why.

## The two-pass hard binding

A manifest's hard binding must hash the asset it describes while excluding
the manifest's own bytes — but where those bytes land in the host's
container format is not known until they are actually embedded, and the
manifest's content (its hash, its signature, its timestamp) is not known
until after that. `BuilderSession` resolves the circularity in one round
trip:

1. It assembles a *placeholder* manifest store — every variable field
   (the hard binding's hash, the claim signature, an RFC 3161 timestamp if
   requested) zero-filled at exactly its final encoded length — and asks
   the host to embed it (`BuilderRequest::ReservePlaceholder`).
2. The host reports back the byte ranges the hard binding must exclude —
   usually the one range of the container structure now carrying the
   placeholder, framing included (a JPEG's `APP11` segment headers belong
   inside it too), but exactly what the format's specification calls for:
   TIFF excludes a length field and the store, which are not adjacent. Up
   to `MAX_EXCLUSIONS`; the placeholder reserves room for that many, and
   the real assertion pads the difference.
3. The session hashes the asset outside those ranges, patches in the real
   hash, and asks the host to sign the claim (`BuilderRequest::Sign`) and,
   if configured, obtain a timestamp (`BuilderRequest::Timestamp`).
4. It patches the real signature (and timestamp) into the very same
   buffer and asks the host to commit it in place
   (`BuilderRequest::CommitManifest`).

Every value that changes between passes is engineered to be either
fixed-length (a digest, a signature at a caller-declared length) or backed
by an exactly-computed padding field, so the buffer's total length never
changes and `replace_payload` always succeeds — see
[`src/jumbf.rs`](src/jumbf.rs), [`src/data_hash.rs`](src/data_hash.rs), and
[`src/cose.rs`](src/cose.rs) for how.

## Status and scope

Builds one manifest (no ingredients, no update manifests) as a C2PA v2
claim, with a `c2pa.hash.data` hard binding (the only binding
`contentauth-c2pa-reader` validates today), caller-supplied opaque
assertions, every C2PA-permitted signing algorithm, and an optional RFC
3161 timestamp. Every manifest this crate builds is exercised, in
[`tests/build_and_read_fixture.rs`](tests/build_and_read_fixture.rs), by
round-tripping it through `contentauth-c2pa-reader` and checking that it
reads back as trusted — that round trip, through an independently-written
reader, is this crate's primary correctness proof.

This crate never builds a v1 claim: v1 is a read-only concern, for
interoperating with manifests this crate did not write (the specification
forbids a claim generator producing one). The v2 claim it writes follows
the specification's `claim-map-v2`: `claim_generator_info` is a single map
carrying `specVersion` (the specification snapshot this repository pins),
and there is no `dc:format` or `claim_generator` — so
`BuilderSettings` takes no MIME type, and a reader reports no `format` for
what this crate builds. Not yet written: `redacted_assertions` (which
has no use without ingredients) and a generator `icon`.

Each caller-supplied assertion carries an `AssertionKind` — `Created` or
`Gathered` — that the host sets: the host supplies the assertion's
content, so it is the one that knows whether this claim's generator
authored it or gathered it from elsewhere, and this crate has no way to
infer that on its own. The claim's `created_assertions` and
`gathered_assertions` are populated accordingly; the hard binding this
session adds itself is always `Created`.

Deliberately out of scope for now: ingredients and update manifests,
BMFF/box-hash hard bindings, OCSP, and certificate decoding or validation
(certificates are passed through opaquely into the COSE `x5chain`; the
host vouches for them).

## Request vocabulary

Defined in [`src/request.rs`](src/request.rs). Any request may be answered
with `BuilderHostReply::Failed` — and, unlike the reader, every host
failure here is fatal: an incomplete or wrongly bound manifest is far more
consequential to persist than an incomplete read report.

| Request | Answered with | Purpose |
|---|---|---|
| `ReservePlaceholder { stream, placeholder }` | the byte range of the container structure now carrying it, framing included | Host embeds a complete, zero-filled-where-pending manifest store into the asset (typically via a [`contentauth-c2pa-format`](../contentauth-c2pa-format) handler). |
| `AssetLength { stream }` | total length in bytes | Needed to know what lies after the reserved placeholder. |
| `AssetBytes { stream, range }` | bytes | Streams the asset (now containing the placeholder) into this crate's hashing, to compute the hard binding. |
| `Sign { alg, data }` | raw signature bytes | Signs a COSE `Sig_structure`; mirrors `c2pa_raw_crypto::RawSigner::sign`. |
| `Timestamp { digest, hash_alg }` | a bare `TimeStampToken` | Obtains an RFC 3161 countersignature; the host owns the TSA round trip. |
| `CommitManifest { stream, range, manifest }` | acknowledgement | Replaces the reserved placeholder with the final manifest bytes — guaranteed byte-identical in length. |

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
[`BuilderSession`]: src/builder.rs
