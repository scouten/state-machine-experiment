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
manifest store from an asynchronously-readable JPEG or TIFF, and report it the
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
  The browser `fromBlob` also accepts optional caller-supplied detached
  manifest-store bytes; the asset is validated against those bytes through
  the same session used for embedded stores.
  Missing/unsupported active claim hash algorithms reject with
  `C2pa(UnknownAlgorithm)`, matching legacy rather than the core's default.
  `context_json` is c2pa-rs settings JSON; `Context::from_json` supports
  separate manifest, timestamp, and CAWG trust anchors, named trust lists,
  and `ocsp_fetch`, which defaults off as in c2pa-rs. The inline facade
  resolves `trust` and `cawgTrust` through the shared `Context` utility.
  Settings the reader cannot honor, including disabled trust verification,
  are rejected at that migration boundary. Remote fetching is enabled only
  through the inline facade's explicit policy-bounded host options, not an
  unchecked settings flag.
* **`web`** (feature, `wasm32-unknown-unknown` only) — the browser end:
  `Blob` for `web_sys::Blob`, `WebPlatform`, and a
  `#[wasm_bindgen]`-exported `WasmReader` whose JavaScript surface
  (`fromBlob`, `activeLabel`, `manifestStore`, `activeManifest`, `json`)
  is c2pa-wasm's own. Its dependencies are declared for that target
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
* **Formats beyond JPEG and TIFF/BigTIFF/DNG** — `src/format.rs` selects
  the workspace registry's handlers, shared with browser/Node signing.
* **The full `@contentauth/c2pa-types` `ManifestStore`** — CBOR assertion
  values, created flags, and active-manifest success/informational/failure
  buckets are now projected. Ingredient relationships, signature metadata,
  thumbnail/resource references, and exact validation-result parity remain
  incomplete. `ManifestStore` stays shared with
  `contentauth-c2pa-rs-compat`.
* **Remote manifests** — `verify.remote_manifest_fetch` now controls whether
  a format-reported URL becomes a host request. `Platform::remote_manifest`
  is the transport seam. Its default and `WebPlatform` decline the request;
  a networked host must enforce URL and response policies before returning
  bytes. JPEG now reports standard XMP references; TIFF and extended XMP
  remain open. `WasmReader.fromBlob` accepts an optional remote-host callback;
  the inline facade supplies it with exact-origin policy, streamed byte limits,
  deadlines, and caller cancellation. HTTP stays in JavaScript and fetching
  stays off by default.
* **Browser OCSP breadth** — the optional `WasmReader.fromBlob` OCSP callback
  now receives the URL and DER request, returning response bytes. The inline
  facade supplies a bounded `fetch` POST host with explicit allowed origins,
  limits, deadline, and cancellation; no callback means the offline behavior
  remains. Fetching is off by default. The reader authenticates DER and retains
  its existing inaccessible/fail-open versus authenticated-revocation policy.
  Real responder interoperability beyond the local signed fixtures remains open.

The [M1 browser prototype](../c2pa-js-state-machine) now executes this adapter
through the combined [browser packaging crate](../contentauth-c2pa-web-bindings)
in Chromium, Firefox, and WebKit. Its five unchanged upstream cases and
read/sign proofs supplement the native suites and portable target checks;
they do not establish full c2pa-web reporting or Worker parity.

## Building

```sh
cargo test -p contentauth-c2pa-js-compat
cargo check -p contentauth-c2pa-js-compat --all-features --target wasm32-unknown-unknown
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

[c2pa-js]: https://github.com/contentauth/c2pa-js
