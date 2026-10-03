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
definition (no RNG in the engine); no async signer; JPEG only.

Timestamping: a definition's `tsa_url`, or `Signer::time_authority_url`,
countersigns the claim with an RFC 3161 timestamp. The request goes out
through `Signer::send_timestamp_request(url, der_request)`, whose default is
a blocking HTTP `POST` (`application/timestamp-query`) — so this crate, like
`contentauth-c2pa-rs-compat`, has a network dependency and is exempt from the
Wasm checks. Override the method to reach an authority another way. An
authority that refuses or cannot be reached fails the build.

Tests (`tests/baseline.rs`) sign the baseline JPEG and read it back through
`contentauth-c2pa-rs-compat`'s `Reader::from_context(..).with_file(..)`:
`Trusted`, label, title, instance id, and the `c2pa.actions.v2` /
`c2pa.hash.data` assertions; plus streams vs. files, an untrusted-anchor
read, a refusing signer leaving no output, and rejected formats.
