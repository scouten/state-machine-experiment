# Test fixtures

## `manifest_data.c2pa`

A raw (unwrapped) C2PA manifest store, copied verbatim from
[c2pa-rs](https://github.com/contentauth/c2pa-rs) at
`sdk/tests/fixtures/ingredient/manifest_data.c2pa`. It was produced by
`make_test_images` 0.33.1 / c2pa-rs 0.33.1 and describes a JPEG asset
(`C.jpg`).

It is used by `tests/read_fixture.rs` as real-world evidence that the
manifest store walk and claim decoder handle bytes written by a production
C2PA implementation — not just the synthetic stores the unit tests build. Among
other things it exercises:

* nested superboxes four levels deep (store → manifest → assertion store →
  assertion);
* a description box with the private/salt toggle set (the
  `stds.schema-org.CreativeWork` assertion carries a `c2sh` salt box);
* `json`, `cbor`, and `bfdb`/`bidb` content boxes side by side;
* a CBOR claim using indefinite-length encoding.

## `C.jpg`

The asset that manifest store was written for, copied from c2pa-rs at
`sdk/tests/fixtures/C.jpg`. The store above is embedded in it at offset 32,
and hashing the asset outside the range its hard binding excludes
reproduces the digest that binding records — which is what
`tests/read_fixture.rs` checks. Having the real asset means the hard
binding is verified end to end against production bytes rather than against
a synthetic stand-in.

Because it is a *raw* manifest store rather than an asset, no
container-format parsing is needed to read it — which suits a crate that
deliberately externalizes container handling to the host.

## `signer-leaf.der`, `signer-issuer.der`

The two certificates from the `x5chain` header of that manifest's claim
signature, extracted verbatim: the end-entity certificate that signed the
claim (RSASSA-PSS, 4096-bit) and the intermediate that issued it. The root
is not in the chain — it would come from a trust list.

They are kept as standalone files so that `src/cert.rs` can be tested
without first going through the COSE layer, and so `tests/cert_contract.rs`
can pin what a certificate decoder must produce. The duplication is not
taken on trust: `tests/cert_contract.rs` checks that both appear verbatim
inside `manifest_data.c2pa`, so a fixture that drifts from the manifest it
came from fails the build.

## `test-signer.der`, `test-signer.key.pem`

A self-signed ECDSA P-256 certificate and its private key, generated for
this repository so that unit tests can build synthetic manifests whose
claim signatures genuinely verify (see `src/test_support.rs`). Before this
existed, synthetic manifests carried a placeholder signature, which meant
every test that read one exercised the *failure* path.

**The private key protects nothing.** It was generated for test data and
has never signed anything else; the certificate says `OU=TEST ONLY - NOT A
REAL CREDENTIAL` in its subject for the benefit of anyone who encounters it
out of context.

## `trust-root.der`, `trust-intermediate.der`, `trust-leaf.der`

A three-level ECDSA P-256 PKI generated with OpenSSL for this repository,
so that `src/chain.rs` can be tested against a chain that genuinely
verifies rather than against certificates spliced together by hand:

* **`trust-root.der`** — self-signed, `CA:TRUE`, key usage
  `keyCertSign`/`cRLSign`, no EKU. Stands as the trust anchor.
* **`trust-intermediate.der`** — issued by the root, `CA:TRUE` with
  `pathlen:0`, same key usage. The `pathlen:0` is deliberate: it is what
  makes a path-length violation testable by splicing an extra
  intermediate in.
* **`trust-leaf.der`** — issued by the intermediate, `CA:FALSE`, key usage
  `digitalSignature`/`nonRepudiation`, EKU `emailProtection`. A
  C2PA-conformant claim signer.

`openssl verify -CAfile trust-root -untrusted trust-intermediate
trust-leaf` reports `OK`, which is the independent oracle the validator in
`src/chain.rs` is held against: the chain was known good before anything
in this repository was written to check it.

The fixtures' validity windows run from their generation date to 2126, so
tests pick a fixed evaluation instant (2027-01-15) rather than reading a
clock — which is also what lets expiry be tested by moving the *instant*
instead of shipping a certificate that has already rotted.

## `trust-leaf-wrong-eku.der`, `trust-leaf-is-ca.der`

Two more leaves from the same intermediate, each violating one rule of the
C2PA end-entity profile and nothing else, so that a test rejecting one is
rejecting it for the stated reason:

* **`trust-leaf-wrong-eku.der`** — EKU is `serverAuth`, a purpose the
  profile does not accept for claim signing.
* **`trust-leaf-is-ca.der`** — `CA:TRUE` with `keyCertSign`, but otherwise
  a perfectly good claim signer (EKU `emailProtection`, key usage
  `digitalSignature`).

## `timestamp-token.der`

The RFC 3161 `TimeStampResp` from the `sigTst` unprotected header of that
manifest's claim signature, extracted verbatim. It was issued by DigiCert
on 2024-08-06T21:53:37Z under policy `2.16.840.1.114412.7.1`, and its
message imprint is SHA-256 of the `CounterSignature` `Sig_structure` over
the fixture's own claim.

Held standalone so that `src/timestamp.rs` can be tested without first
going through the COSE layer — the same reason `signer-leaf.der` exists.
Like the certificates above, it is checked against drift: it must appear
verbatim inside `manifest_data.c2pa`.

Everything a timestamp needs travels inside it, so the negative cases are
built by corrupting this one byte by byte rather than by minting new
tokens: altering the encapsulated `TSTInfo` exercises the `message-digest`
check, altering the trailing signature exercises the authority's signature
check, and validating it against different bytes exercises the message
imprint check.

## `digicert-trusted-root-g4.der`

*DigiCert Trusted Root G4*, the self-signed root of the chain that
timestamp token carries, extracted from the token itself. Configuring it
as a timestamp trust anchor is what lets `tests/read_fixture.rs`
demonstrate the point of a timestamp: the same fixture, read at an instant
past its signer's 2030 expiry, is `Invalid` without this anchor and
`Trusted` with it.

A public root certificate, reproduced here only so the test is
self-contained. It is checked against drift the same way.
