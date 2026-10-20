# contentauth-c2pa-wasm

Synchronous wasm-bindgen adapters over
[`contentauth-c2pa-session-bridge`](../contentauth-c2pa-session-bridge/README.md),
for a JavaScript host running in a browser Worker.

- `ReadSession` exposes the read bridge's `advance` / `fulfill` / `finish`
  cycle as plain JSON requests plus typed reply methods (`bytes`, `length`,
  `time`). OCSP and other network requests are rejected: this binding is
  offline.
- `BuildSession` does the same for baseline ES256 JPEG signing. It receives
  only public certificates; the host signs each `sign` request's data itself and
  replies with `signature`.

Nothing here performs I/O, async work or threading, and nothing here knows
what a Worker is: the host owns the event loop, the asset and the key.

This crate is deliberately **not** a member of the root workspace (it has its
own `[workspace]`). It builds only for `wasm32-unknown-unknown`, and
`wasm-bindgen` is pinned with `=` because the generated JavaScript glue must
match the schema version of the `wasm-bindgen` CLI that post-processes the
module. Build it with `wasm-pack`/`wasm-bindgen` at the matching version.
