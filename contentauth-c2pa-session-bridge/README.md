# C2PA session bridges

The runtime-neutral binding surface used by the shared [JavaScript host](../js/)
through [Wasm](../contentauth-c2pa-wasm/) and the existing Neon addons.

- `read::ReadSessionBridge` wraps `FileReadSession`.
- `build::BuildSessionBridge` wraps `FileBuilderSession`.
- `compat` owns shared SDK-shaped settings, format selection, errors and reports.

These are the existing implementations formerly owned by
`contentauth-c2pa-node-compat` and `contentauth-c2pa-node-compat-sign`, moved and
renamed rather than copied. The browser async host now imports the same
compatibility vocabulary instead of owning it.

Hosts call synchronous `advance`, answer any subset of requests using `fulfill`,
and consume a completed session with `finish`. Numeric handles, strings and owned
bytes cross the binding; the bridge does not perform I/O, spawn, await or hold
private keys. Errors, request ordering and one-time request reporting are
unchanged. Read/build request vocabularies remain separate modules.

Bulk write payloads and completed build manifests retain the engine's shared
immutable `Bytes` storage. Describing or cloning a write request does not copy its
buffer. Hosts can borrow a byte slice for their language boundary; a host-owned
`Vec<u8>` read reply moves into the engine's `Bytes` without copying. This is not
an end-to-end zero-copy ABI: Neon/Wasm still copy into JavaScript-owned buffers.

Compatibility policy remains explicit: registry-backed JPEG/TIFF/DNG selection,
settings JSON, baseline definition conversion and reports are not generic
engine concepts.
The [C++ binding](../contentauth-c2pa-cpp/) also consumes both bridges
through a C ABI with its own ownership adapter. The
[Python package](../contentauth-c2pa-python/) links that same C ABI
through compiled CFFI and exposes typed low-level read/build sessions, blocking hosts
and an atomic file-signing helper; its async hosts and other bindings remain prospective.
Rust enums are not a stable cross-language ABI.

The older browser-shaped async hosts remain in
[`contentauth-c2pa-js-compat`](../contentauth-c2pa-js-compat/) and its signing
companion. They are alternative hosts, not dependencies of this bridge.
Existing addon JavaScript drivers retain file, OCSP and timestamp behavior that
the new in-memory shared Worker host does not yet implement.

```sh
cargo test -p contentauth-c2pa-session-bridge
```

The moved integration tests preserve synchronous drive behavior, compare the
read bridge with the async host, and validate signing through the Rust reader.
