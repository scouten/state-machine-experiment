# contentauth-c2pa-node-compat-sign

The Rust half of the Node binding of the baseline signing case:
`NodeBuildSession`, a purely synchronous `advance` / `fulfill` / `finish`
wrapper over `FileBuilderSession<JpegFormat>` with the engine's types
flattened to plain data (`PendingRequest::{Read, Length, Write, Sign}`,
`Reply`, `SignReport`). Node owns the event loop, the files and the signing
key; Rust never blocks, spawns or sees a key. The write-side twin of
`contentauth-c2pa-node-compat`; the Neon addon and JavaScript driver are in
[`c2pa-node-sign-addon`](../c2pa-node-sign-addon).

`tests/sync_drive.rs` drives it with a plain synchronous loop and reads the
signed result back through `contentauth-c2pa-rs-compat`.
