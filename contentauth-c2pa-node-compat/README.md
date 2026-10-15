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
c2pa-node and c2pa-wasm both sit on c2pa-rs's `Reader`. Both read and sign
adapters use the shared registry selector for JPEG and TIFF/BigTIFF/DNG aliases.
The Node session still performs no I/O.

`Reader::json` returns `Result<String, serde_json::Error>` and uses the shared
legacy display formatter: nonempty all-number arrays in object fields become
base64 (unsigned integers' low byte; negative/floating-point entries omitted).
The Rust `active_manifest` object retains its arrays. The Neon addon propagates
serialization errors rather than constructing an empty successful reader.
Its JavaScript reader is built from JSON, so its cached accessors use that JSON
view. A newly signed numeric assertion tests the shared formatting through both
real addons.
The same shared projection reports resource-free v1/v2/v3 ingredients and
owner-qualified unknown-provenance deltas. A newly signed ingredient is checked
through both actual addons. Assertion review ratings, creation time and custom
metadata use the same projection and JSON formatting. Reviews do not become
validation statuses or lower a trusted result; malformed ratings and unsupported
structured metadata references fail at report serialization.
Linked/history fields and unsupported resource targets reject at
serialization rather than silently publishing incomplete provenance; a failed
read does not poison subsequent supported reads.

`Reader::resource_bytes` borrows retained embedded bytes with the same exact,
unique absolute self JUMBF URI lookup as the browser reader. The Neon addon
copies them into an independent `Buffer`; JavaScript's `resourceToAsset` writes
buffer/file destinations with c2pa-node's result shape and asynchronous host file
I/O. Claim thumbnails, generator icons and ingredient thumbnails/data work after
the source closes, without reads/fetches or a trust-state change. The JS reader
now retains an immutable native handle until garbage collection, not just JSON;
payload copies are synchronous, not a large-resource streaming facility.
Databox/external/missing/ambiguous references remain explicit failures.

`NodeSession::new(format, settings_json, manifest_store)` now accepts optional
detached bytes via the existing file session, without adding request kinds or
I/O. Hosts pass `None` for the previous located-store behavior. Detached bytes
take precedence without fallback; asset bytes are still validated. The resulting
reader's `is_embedded` is false and `remote_url` empty. The addon exposes the
legacy `fromManifestDataAndAsset` constructor with a pre-await buffer snapshot.
Actual Node tests compare the complete trusted report with a real c2pa-rs
detached-resource golden; native tests compare the async browser host, retain
resource extraction and prove tamper/error recovery. Full Node settings/Context
and size-limit surface parity remain separate.

Not covered: databox resources, full `Builder`,
signers, identity assertions, Trustmark, and formats beyond JPEG/TIFF.

[c2pa-node]: https://github.com/contentauth/c2pa-js/tree/main/packages/c2pa-node
