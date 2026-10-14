# contentauth-c2pa-primitives

Shared vocabulary and deterministic encoders for the sans-I/O C2PA crates in
this workspace: [`contentauth-c2pa-reader`](../contentauth-c2pa-reader) and
`contentauth-c2pa-builder`.

Both of those crates are independent [`contentauth-state-machine`](../contentauth-state-machine)
sessions, each with its own request vocabulary and settings/result types —
that separation is deliberate (see the workspace [`CLAUDE.md`](../CLAUDE.md)).
This crate exists for the narrow slice of the two that is genuinely the same
thing in both directions rather than something either would reasonably
reimplement on its own:

- `StreamId`, `ByteRange` — opaque stream/range handles.
- `HashAlgorithm` — SHA-256/384/512, digest computation, C2PA name and OID
  mapping. Verifying a hash and computing one to record are the same
  operation.
- `SigningAlg` — the C2PA-permitted signature algorithms, their COSE
  algorithm-ID mapping (RFC 9053), and their paired hash algorithm.
- `HashedUri` — the `{url, alg?, hash}` reference a claim, an identity
  assertion, or an ingredient makes to a JUMBF box. `HashedUri::from_box`
  hashes a box's *contents* (stripping the 8/16-byte header itself, so no
  caller can hash the wrong span); it builds no JUMBF and does no I/O.
- `EncodedAssertion` — the opaque (label, CBOR) pair independent
  assertion crates hand to the rest of the system.
- `HostError` — the "the host couldn't do it" wrapper every sans-I/O
  session's reply vocabulary needs.
- `cbor::sig_structure` — the COSE `Sig_structure` (RFC 9052) a claim
  signature covers, hand-encoded for determinism. The reader reconstructs
  these bytes to verify a signature; a builder constructs the identical
  bytes to produce one. A disagreement between two independent
  implementations of this one function would be a serious bug — a
  signature that verifies against the wrong bytes, or a correct signature
  that appears broken — so it lives here once instead of twice.

- `tsa` — the RFC 3161 `TimeStampReq` encoder and `TimeStampResp`
  unwrapper: the deterministic halves of a timestamp authority round trip,
  whose network half is always the host's.

See the crate's rustdoc (`cargo doc -p contentauth-c2pa-primitives --open`)
for the full API.
