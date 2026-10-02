# contentauth-c2pa-js-compat-sign

The **JS/Wasm** binding of the [baseline signing case](../contentauth-c2pa-sign-baseline),
the write-side companion to [`contentauth-c2pa-js-compat`](../contentauth-c2pa-js-compat):
an `async` `Builder::sign(signer, format, blob)` whose signer is whatever
asynchronous thing the host has — in a browser, a `Promise` from WebCrypto
(a non-extractable `CryptoKey` never enters Wasm memory), a remote signing
service, a hardware token.

```rust
pub trait AsyncSigner {
    fn alg(&self) -> SigningAlg;
    fn certs(&self) -> Vec<Vec<u8>>;
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError>;
}
let SignedAsset { asset, manifest } = builder.sign(&signer, "image/jpeg", &blob).await?;
```

The source is the read side's own `Blob` trait; the output is assembled in a
`Vec<u8>` (a browser has no file, and the engine reads back what it wrote to
hash it). Nothing below `src/drive.rs` is async — it is the same
`FileBuilderSession` the blocking Rust host drives, with an `.await` at each
host answer.

With the `web` feature (compiled only for `wasm32-unknown-unknown`)
`src/web.rs` exports `WasmBuilder` — `fromJson(json)` and
`await sign({ alg, certs, sign }, format, blob)` →
`{ asset, manifest }` — over a JavaScript signer object. **Not run in a
browser** (there isn't one here): it is held to
`cargo check --all-features --target wasm32-unknown-unknown`, like
`contentauth-c2pa-js-compat`'s `web` module.

Tests (`tests/baseline.rs`, a hand-rolled executor, no runtime): a signer and
blob whose every call suspends, read back `Trusted` through the read-side
async host; agreement with the blocking host; two builds interleaving on one
thread; signer/blob failure; rejected formats and definitions. ECDSA
signatures are randomized, so "agreement" compares layout and the reader's
JSON, not bytes.
