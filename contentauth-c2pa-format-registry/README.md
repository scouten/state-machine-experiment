# contentauth-c2pa-format-registry

Host-side format detection and run-time handler dispatch for the sans-I/O
C2PA sessions in this workspace.

The sessions — reader, builder, and the file sessions that compose them
with a container format — never decide *which* format they are handling:
they are generic over a [`FormatHandler`](../contentauth-c2pa-format) the
host hands them. This crate is the host's half of that bargain.

## Where the seams are

```text
  host                          this crate                      the core (unchanged)
  ────                          ──────────                      ────────────────────
  reads `registry.window()`  →  Registry::detect(header)
  bytes however it likes        Registry::by_extension(ext)  →  AnyFormat  →  FileReadSession<AnyFormat>
  (read, await, cache)          Registry::by_mime(mime)                       FileBuilderSession<AnyFormat>
                                        ▲
     policy: which of the three,        │ FormatDescriptor: plain data each handler publishes
     in what order, is the host's       │ (name, MIME types, extensions, byte signatures)
```

* **Detection is a pure function of bytes in hand.** The registry never
  reads an asset. It says how much it needs (`window()`), the host reads
  that — once, however many formats are registered — and `detect` answers.
  Whether the host does so with a blocking `read`, an awaited
  `Blob.slice`, or a cached prefix is its own affair; the async host in
  `contentauth-c2pa-js-compat` and the synchronous one in
  `contentauth-c2pa-rs-compat` would use the same two calls.
* **Policy stays out.** Content is evidence; a file name or `Content-Type`
  is a claim. A registry offers all three lookups and no opinion on how to
  combine them. `contentauth-c2pa-rs-compat`'s `src/format.rs` — the whole
  of that host's format logic — says: content first, extension second,
  else unsupported.
* **Nothing below the host knows.** `FileReadSession<AnyFormat>` is
  `FileReadSession<H>` with `H = AnyFormat`; no session, no contract crate
  and no other format crate changed to make TIFF selectable. Adding a
  format is a crate implementing the contract plus a registration — in
  `Registry::standard`, or a `register` call in the host that wants it.
* **Formats are features.** `jpeg` and `tiff` are optional dependencies,
  so a host picks what it ships, and this is the only crate that names more
  than one format.

## The two types

* `AnyFormat` — a cheap, cloneable handle that is itself a `FormatHandler`:
  boxed operations (one allocation each, nothing beside an I/O round trip).
  `AnyFormat::new(handler)` wraps a Rust handler.
* `DynFormatHandler` — the object-safe face of a handler: a descriptor,
  `locate`, `plan_embed`, `commit`. Rust handlers do not implement it (use
  `AnyFormat::new`); a handler that is not a Rust `FormatHandler` does, and
  is wrapped with `AnyFormat::from_dyn`. The tests do exactly that.

The type-erased handler is held to the same contract as a concrete one:
the conformance suite runs against it (`tests/registry.rs`).

## Looking ahead: formats in other languages

Not built here, but the shape was chosen so it could be.

**What crosses the boundary is already plain data.** A descriptor is names,
media types, extensions, and `(offset, bytes)` signatures — no function
pointers — so a handler written elsewhere publishes it as JSON (or, for a
host in another language that never calls into Rust, the *host* can run
detection from a table of descriptors with no Rust at all: it is the same
rule as `shared-mime-info`'s magic). Operations speak `IoRequest::Read` /
`Length` and return a `ManifestLocation` or `EmbedPlan` — byte ranges and
byte vectors, no callbacks, no borrowed streams.

**An operation is a coroutine, which most languages have.**
`locate`/`plan_embed` are state machines that yield "read this range" and
are resumed with the bytes — precisely a generator:

```js
// A TIFF handler's locate, in JavaScript (sketch)
function* locate(stream) {
  const length = yield { length: stream };
  const header = yield { read: { stream, start: 0, len: 8 } };
  // …follow the IFD chain, yielding a read for each…
  return { embedded: { jumbf, range } };
}
```

Python generators, Kotlin sequences, C# iterators, and Swift/Rust `async`
fit the same mould. A language without them writes the explicit
`advance`/`fulfill`/`finish` machine `contentauth-c2pa-node-compat`'s
`NodeSession` already exposes.

**The adapter is one `DynFormatHandler`.** For each target there is one
Rust type that implements it by driving the foreign operation:

| Target | How the handler is reached | Adapter |
|---|---|---|
| Wasm component / WASI | A WIT resource with `advance`/`fulfill`/`finish`, plus `descriptor()` and `commit()` functions | `DynFormatHandler` over a component instance |
| JS (Neon, wasm-bindgen) | The generator above, stepped by the adapter | `DynFormatHandler` over a persistent JS object |
| C ABI / Python / JVM | An opaque handle and four functions (`descriptor_json`, `begin_locate`, `step`, `commit`) | `DynFormatHandler` over function pointers |

Because every operation yields to the host rather than doing its own I/O,
a foreign handler needs no filesystem, network, or async runtime of its
own, and the host's reads stay where they are today: answering requests.
`commit` is the exception, a plain function of a plan and the final store
bytes.

**Two hard parts, honestly.**

1. *Marshalling `EmbedPlan`.* It is plain data, but `EmbedPlan::check` is
   the invariant everything leans on. The adapter should run it on
   whatever a foreign handler returns — `FileBuilderSession` already
   re-checks plans rather than trusting a handler it does not control.
2. *`Send`.* Sessions are `Send`; a foreign handle may be pinned to a
   thread (a JS isolate, a Python GIL holder). The adapter owns that
   (a channel, or a thread-affine wrapper), not the contract.

A real conformance story for foreign handlers wants the suite as data too:
`test_util::conformance` generalised to run from a corpus of
`(unsigned asset, store)` fixtures that any language can load, rather than
only from Rust test code.

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
