# contentauth-c2pa-rs-compat-sign

The **synchronous Rust** binding of the [baseline signing case](../contentauth-c2pa-sign-baseline):
`Builder::from_json`, `Builder::sign`, `Builder::sign_file`, and a `Signer`
trait, shaped after [c2pa-rs](https://github.com/contentauth/c2pa-rs)'s own,
over `contentauth-c2pa-file-builder`'s blocking `build_and_sign` host.

```rust
let builder = Builder::from_json(definition_json)?;
let manifest: Vec<u8> = builder.sign_file(&signer, "in.jpg", "out.jpg")?;
```

`sign_file` publishes atomically (temp file + rename; a failed build leaves
the destination untouched). `sign` takes any `Read + Seek` source and
`Read + Write + Seek` destination.

Differences from c2pa-rs: `instance_id`/`label` are required in the
definition (no RNG in the engine); no timestamping, no async signer;
JPEG only.

Tests (`tests/baseline.rs`) sign the baseline JPEG and read it back through
`contentauth-c2pa-rs-compat`'s `Reader::from_context(..).with_file(..)`:
`Trusted`, label, title, instance id, and the `c2pa.actions.v2` /
`c2pa.hash.data` assertions; plus streams vs. files, an untrusted-anchor
read, a refusing signer leaving no output, and rejected formats.
