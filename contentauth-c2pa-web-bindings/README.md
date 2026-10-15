# contentauth-c2pa-web-bindings

A browser `cdylib` combining the existing reader and baseline-signing adapters.
`BrowserReader` and `BrowserBuilder` delegate to those adapters; they do not add
another engine, format handler, or signing implementation.
`BrowserReader.fromBlob` accepts optional detached manifest-store bytes for
assets without an embedded store.

The browser exports exist only on `wasm32-unknown-unknown`. Native and WASI
builds retain the empty packaging crate, without browser dependencies.

The [JS package](../c2pa-js-state-machine/README.md) builds the Wasm artifact,
generates browser JS with a matching wasm-bindgen CLI, and supplies the inline
compatibility facade and runtime tests. Full SDK parity remains future work.
