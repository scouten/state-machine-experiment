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

Compatibility policy remains explicit: JPEG selection, settings JSON, baseline
definition conversion and reports are not generic engine concepts. C++, Python
and other hosts could supply their own ABI/ownership adapters, but none are
implemented or tested. Rust enums are not a stable cross-language ABI.

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
