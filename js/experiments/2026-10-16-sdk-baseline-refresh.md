# Reference SDK baseline refresh: c2pa-rs 0.91.3

## Baseline

Future parity comparisons use the sibling `c2pa-js` checkout on upstream `main`:

| Component | Version / revision |
| --- | --- |
| c2pa-js | `20531aa26a219fee35937d3a51a77ebf7a0c03ef` |
| c2pa-rs | `0.91.3`, pinned exactly by the SDK workspace |
| c2pa-node | `0.9.10` |
| c2pa-web | `0.15.4` |
| c2pa-wasm | `0.13.3` |

The checkout was fast-forwarded from `3c642db` to upstream main. Existing
untracked Scout/workspace files were preserved; no tracked SDK edits were made.
Both native and Wasm artifacts were rebuilt from this checkout, rather than
assuming a new Cargo.lock meant an existing binary used the new dependency.

## Build and comparison

From the sibling `c2pa-js` root:

```sh
git pull --ff-only origin main
cargo tree --locked -p c2pa --depth 0
pnpm --filter @contentauth/c2pa-node build
wasm-pack build packages/c2pa-wasm --target web --release --locked
```

The Node command rebuilds the release addon and TypeScript distribution.
wasm-pack builds release Wasm and generates matching JavaScript glue; its
matching wasm-bindgen CLI is managed separately from the experimental binding's
pinned CLI. The web comparison preparation bundles the current facade/Worker.

From this repository's `js/` directory:

```sh
npm run benchmark:sdk
```

Comparison preparation now checks that the SDK lockfile resolves c2pa-rs
`0.91.3`, records the resolved version in provenance and rejects a different
version until the documented baseline is explicitly revised. Both `benchmark:sdk`
and `benchmark:blob` run preparation. This check is not binary attestation:
rebuild SDK artifacts after any subsequent checkout/dependency update.

The rebuilt artifact SHA-256 hashes for this refresh:

| Artifact | SHA-256 |
| --- | --- |
| Node addon | `f357e42770bc0e5c521a1593cdca966eb07eabd181c2b0ea75a1c3c3b28c650f` |
| Wasm | `6cba70b032ef4bd2ed71b56660858a9e1e35c1cb45e84af1a581f71b772cf133` |
| Wasm JS glue | `5d7695665d9f213753c339e6e82d8a2fd9574de64dab00c802f993d7cf8e105b` |
| SDK Cargo.lock | `b1ac3c72c7729e929bab27996a7181646dd6cc75ad1f5154f5f7a9cda3e530d7` |

## Historical evidence

The earlier [SDK performance](2026-10-16-sdk-performance.md) and
[File/Blob memory](2026-10-16-file-blob-memory.md) reports retain their original
SDK versions and measurements. They are not silently relabeled as 0.91.3 results.
The [native validation-gap reproduction](2026-10-16-validation-parity.md)
already used c2pa-rs 0.91.3 independently.

Current rerun samples and updated provenance live in ignored `results/sdk-*.json`.
The refreshed run passed **192 measured operations**: 48 each in Node,
Chromium, Firefox and WebKit, plus warmups and validation. Every sign output was
accepted as `Trusted` by both readers, and both rejected tampered inputs.
This refresh verifies the comparison setup; it is not a controlled
before/after attribution of changes in SDK performance.

[All experiment reports](README.md)
