# contentauth-c2pa-js-compat

An experimental compatibility layer: a slice of [c2pa-js]'s `c2pa-wasm`
reader API — the Rust side of the C2PA web SDK — reproduced on top of this
workspace's sans-I/O read engine, with the asynchrony that API promises
living *here*, at the interface-specific layer, and nowhere below it.

## Why this crate exists

[`contentauth-c2pa-rs-compat`](../contentauth-c2pa-rs-compat) asked how
much of c2pa-rs's *synchronous, blocking* `Reader` surface this
workspace's engine can reproduce faithfully. This crate asks the same
question of the other public surface built on c2pa-rs: `c2pa-wasm`'s
`WasmReader`, whose `fromBlob(format, blob, contextJson)` is an `async fn`
handed to JavaScript as a `Promise`, followed by synchronous
`activeLabel()`, `manifestStore()`, `activeManifest()`, and `json()`.

c2pa-wasm is async because c2pa-rs's `Reader::with_stream_async` is async,
and that is async because parts of c2pa-rs (trust and revocation checks
that may reach the network) are. Asset *bytes*, though, have to reach
c2pa-rs through a synchronous `Read + Seek` stream — so c2pa-wasm's
`BlobStream` is built on `FileReaderSync`, an API that exists only inside
a Web Worker, and c2pa-web's whole reader lives in one as a result.

This workspace's engine has no opinion about any of that. A
`FileReadSession` never blocks, never awaits, and parks itself with a list
of requests whenever it needs bytes, the time, or the network. Which layer
turns those requests into `.await` points is the host's choice, and this
crate makes it at the c2pa-wasm-shaped interface — where c2pa-wasm makes
it — so that *every* host interaction, asset bytes included, is a real
`.await`. A `Blob` can be read with `Blob.slice().arrayBuffer()`, a
`Promise` available on the main thread, just as readily as with
`FileReaderSync`.

## What this covers

One use case, worked through end to end: **read and validate a C2PA
manifest store from an asynchronously-readable JPEG, and report it the
way c2pa-wasm does.**

```rust,no_run
use contentauth_c2pa_js_compat::{OfflinePlatform, Reader};

# async fn example(jpeg: Vec<u8>) -> Result<(), contentauth_c2pa_js_compat::Error> {
let reader = Reader::from_blob("image/jpeg", &jpeg, None, &OfflinePlatform).await?;
println!("{}", reader.active_label().unwrap_or_default());
println!("{}", reader.json());
# Ok(())
# }
```

The pieces, bottom up:

* **`Blob`** — the asset, as the two operations a JavaScript `Blob`
  actually offers: a synchronous `size` and an asynchronous read of a
  byte range. Implemented for `[u8]`/`Vec<u8>` (always ready) and, under
  the `web` feature, for `web_sys::Blob`.
* **`Platform`** — what a read needs that is not the asset: the current
  time and, optionally, an OCSP transport. c2pa-rs gets both implicitly
  from whatever it was compiled for; a sans-I/O engine gets them
  explicitly, so `from_blob` takes one more argument than `fromBlob`
  does. `OfflinePlatform` (system clock, no network) ships for native and
  WASI hosts; `web::WebPlatform` (`Date.now()`, no network) for the
  browser.
* **`read_manifest`** — the async host: the loop that drives a
  `FileReadSession`, awaiting the `Blob` and `Platform` for each request.
  The only `.await`s in this crate are in that function. Compare
  `contentauth-c2pa-file-reader`'s synchronous `read_manifest`: the same
  loop, the same session type, minus the awaits.
* **`Reader`** — `WasmReader`, method for method. `Error` reproduces
  c2pa-wasm's error-string contract (`format!("{err:?}")`) down to the
  `C2pa(JumbfNotFound)` string c2pa-web's `reader.ts` turns into `null`.
  `context_json` is c2pa-rs settings JSON; the slice recognized is
  documented on `Context::from_json` (trust anchors as PEM, `ocsp_fetch`,
  `remote_manifest_fetch`; everything else ignored).
* **`web`** (feature, `wasm32-unknown-unknown` only) — the browser end:
  `Blob` for `web_sys::Blob`, `WebPlatform`, and a
  `#[wasm_bindgen]`-exported `WasmReader` whose JavaScript surface
  (`fromBlob`, `activeLabel`, `manifestStore`, `activeManifest`, `json`)
  is c2pa-wasm's own. This is the one module in the workspace that names
  a wasm-bindgen type; its dependencies are declared for that target
  alone, so the feature is a no-op everywhere else and nothing below this
  crate changes.

## What the tests demonstrate

`tests/async_host.rs` drives `Reader::from_blob` with a `Blob` whose
every read genuinely suspends (returns `Pending` once, the way a real
`Promise` would), on a hand-rolled executor rather than an async runtime,
and checks what that buys:

* the read completes correctly across every suspension, and reports
  exactly what `contentauth-c2pa-file-reader`'s synchronous host reports
  for the same asset — same engine, different host;
* the future suspends once per host request and nowhere else, so a large
  asset's hard-binding hash is computed in cooperative slices rather
  than one synchronous stall;
* two reads driven round-robin on one thread interleave at every request
  boundary — what a browser's event loop would see if `fromBlob` were
  called twice without awaiting the first, and what a
  `FileReaderSync`-backed stream can never do because it never yields;
* a host failure crosses the suspension intact, carrying the host's own
  description.

`tests/read_signed_jpeg.rs` covers the c2pa-wasm surface itself: trust
anchors arriving as PEM inside settings JSON, the `manifestStore()` /
`activeManifest()` / `json()` shapes, and each error the surface can
produce, including the exact `C2pa(JumbfNotFound)` string.

## What isn't covered yet, and how it would be

* **`fromBlobFragment`** — needs a fragmented-BMFF `FormatHandler`, which
  does not exist yet; then it is a second constructor over the same loop
  with two `Blob`s.
* **`resourceToBytes`, `crJson`** — depend on resource and thumbnail data
  the engine does not decode yet.
* **Formats other than JPEG** — `src/format.rs` is the seam, exactly as
  in `contentauth-c2pa-rs-compat`.
* **The full `@contentauth/c2pa-types` `ManifestStore`** — ingredients,
  decoded assertion values, thumbnails. `ManifestStore` carries the
  top-level contract, populated with what the engine reports today, in
  the same shape `contentauth-c2pa-rs-compat`'s `Reader::json` produces.
* **A `fetch`-backed OCSP transport for the browser** — a `Platform`
  whose `ocsp` posts through `fetch`. `WebPlatform` declines OCSP today
  (fail-open, and c2pa-rs's own default is off); a host that wants it
  implements `Platform` itself.
* **Running the `web` module** — there is no browser in CI. It is held
  to `cargo check --all-features --target wasm32-unknown-unknown`, which
  CI runs, and to the shape of the code it delegates to, all of which is
  tested natively.

## Building

```sh
cargo test -p contentauth-c2pa-js-compat
cargo check -p contentauth-c2pa-js-compat --all-features --target wasm32-unknown-unknown
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

[c2pa-js]: https://github.com/contentauth/c2pa-js
