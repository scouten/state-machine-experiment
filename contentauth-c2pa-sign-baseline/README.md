# contentauth-c2pa-sign-baseline

The **baseline signing case** every binding of the write path is held to.

> Take a JPEG. Describe a manifest for it as c2pa-rs-shaped JSON — a title,
> one claim generator, one `c2pa.actions.v2` assertion with a single
> `c2pa.created` action. Sign it with ES256 and a certificate chain the host
> holds. The output must read back as `Trusted` through
> `contentauth-c2pa-reader`, with the label, title and assertions put in,
> and a hard binding that excludes exactly the reported manifest range.

No ingredients, thumbnail, timestamp, or second assertion — the point is to
exercise every seam a binding has (definition in, a host-held key reached
through the binding language's own kind of asynchrony, asset in, asset out)
with nothing else in the way.

This crate holds only the language-free part: `Definition::from_json` and
`Definition::into_settings(alg, certificates)`, turning the
definition plus what a *signer* decides into `BuilderSettings`. Bindings:

| Binding | Crate | Signer | Asset in / out |
|---|---|---|---|
| Rust, synchronous (c2pa-rs `Builder` shape) | [`contentauth-c2pa-rs-compat-sign`](../contentauth-c2pa-rs-compat-sign) | `Signer` trait | `Read + Seek` / `Read + Write + Seek`, or paths |
| JS/Wasm, async (c2pa-wasm shape) | [`contentauth-c2pa-js-compat-sign`](../contentauth-c2pa-js-compat-sign) | `AsyncSigner` → JS `Promise` | `Blob` / `Vec<u8>` |
| Node, Rust fully synchronous | [`contentauth-c2pa-node-compat-sign`](../contentauth-c2pa-node-compat-sign) + [`c2pa-node-sign-addon`](../c2pa-node-sign-addon) | JS async callback (`node:crypto`, KMS, …) | Node owns the files |

`instance_id` and `label` are required in the definition: the engine has no
RNG, so the host mints them.

The `fixtures` feature exposes the repository's existing test signer and
test JPEG, so all bindings start from the same bytes.
