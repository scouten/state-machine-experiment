# contentauth-c2pa-assertion-data-hash

The `c2pa.hash.data` assertion as an independent, composable element.
Nothing here knows about claims, JUMBF or signing; the crate's whole output
is an `EncodedAssertion` (a label and opaque CBOR), so whatever composes it
cannot come to depend on its fields.

Two ways in: `DataHash` (a digest already in hand), or `DataHashSession`, a
sans-I/O `Session` that asks its host for the asset's length and bytes,
hashes outside the configured exclusions in bounded memory (an 8 × 64 KiB
window), and finishes with the encoded assertion.
