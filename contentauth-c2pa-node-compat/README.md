# contentauth-c2pa-node-compat

An experimental compatibility layer for [c2pa-node]'s reader, built on one
premise: **Rust does no asynchronous work, and Node.js does all of it.**

The crate is a `NodeSession` with three synchronous methods —
`advance`, `fulfill`, `finish` — which is the engine's own interaction
contract with its types flattened into plain data (`PendingRequest`,
`Reply`). No runtime, thread, lock, `async`, or blocking call exists in it
or below it. The Neon binding and the JavaScript driver loop that make it
a drop-in `Reader.fromAsset` live in
[`../c2pa-node-compat-addon`](../c2pa-node-compat-addon), which is where
to read about the design and the measurements.

Settings JSON, manifest-store JSON, and the error-string contract are
reused from [`contentauth-c2pa-js-compat`](../contentauth-c2pa-js-compat):
c2pa-node and c2pa-wasm both sit on c2pa-rs's `Reader`.

Not covered: `fromManifestDataAndAsset`, `resourceToAsset`, `Builder`,
signers, identity assertions, Trustmark, and every format but JPEG.

[c2pa-node]: https://github.com/contentauth/c2pa-js/tree/main/packages/c2pa-node
