# Vertical-slice capability matrix

**Question.** For each capability the Rust workspace implements, is it
reachable and correct through the JS entry points, and what layer would close
each gap?

**Constraint.** No Rust change. Gaps are classified by what closes them:
`js` (shared host / facade), `glue` (Neon or Wasm binding code), `rust`
(neutral bridge or domain crates).

**Method.** [`test/matrix.test.mjs`](../test/matrix.test.mjs)
(`npm run test:matrix`) probes each row and asserts *today's observed outcome*,
so the matrix fails whenever a gap opens or closes without this report being
updated. It writes `results/vertical-matrix.json`. Fixtures are generated at
test time: per-algorithm certificates (openssl), a local fake TSA, and a
CA + leaf chain with an AIA OCSP URL.

## Gaps closed in this experiment (JS only)

- **Signing algorithms.** The shared host and Worker client were hard-wired to
  ES256. They now carry the signer's `alg` end to end and check signature
  width per algorithm (ES256 64, ES384 96, ES512 132, Ed25519 64 bytes).
  ES384, ES512 and Ed25519 sign and read back `Trusted` through the Node
  Worker host.
- **RFC 3161 timestamps.** The Worker answers the Rust-built `TimeStampReq`
  with a `fetch` POST (`application/timestamp-query`, http/https only,
  redirects refused, 1 MiB response cap). Refusal status, HTTP 500, malformed
  bodies and non-http URLs fail the build and leave no output or temp file.

## Matrix

| Capability | Result | Class | Evidence |
|---|---|---|---|
| Sign ES256 / ES384 / ES512 / Ed25519 (Node) | pass | — | read back `Trusted` |
| Sign PS256 / PS384 / PS512 | pass | — | *(closed in the bridge)* the signature length is derived from the leaf certificate's RSA modulus |
| Wasm signing algorithm / format / identities | pass | — | *(closed in the glue)* `BuildSession(definition, format, alg, certs, identities)`; construction verified in Node, browser contracts rerun |
| Timestamps, Node | pass | — | fake TSA saw the POST; token in manifest |
| Timestamps, Wasm | fail | glue | `advance` rejects Timestamp; no reply method |
| Timestamp URL/transport override | missing | js | the older standalone Neon host allowed it; Worker uses `fetch` only |
| Custom trust anchors | pass | — | `Trusted` with anchor, `Valid` without |
| TIFF read/sign (Neon, Wasm) | pass | — | *(closed in the bridge)* `for_format` resolves through the standard format registry (JPEG, TIFF/BigTIFF/DNG); a TIFF signed from JS reads back `Trusted` |
| Format detection in Node host | caller-named only | js | `format` option selects a handler (default JPEG); no content detection |
| Live OCSP read, Node | fail | js | "unsupported host request: ocsp"; needs an SSRF policy (older addon has `ocspPolicy`) |
| Live OCSP read, Wasm | fail | glue | `ReadSession.advance` errors "outside this offline proof" |
| CAWG identity signing | pass | — | *(closed in the bridge)* `signer.identities` with their own key and algorithm; the sign request carries the assertion label |
| CAWG identity reading | fail | rust | an identity-bearing asset reads `Trusted`, but the c2pa-js-shaped report has no identity section |

## Findings

1. Roughly half of the apparent gaps were JS-only and are now closed; the
   algorithm guard was the largest single one.
2. The bridge exposed only a baseline slice of what the Rust crates already
   do. TIFF, RSA-PSS and CAWG identity signing are now closed there (the
   bridge takes formats from the registry, derives the RSA length from the
   leaf certificate, and accepts identity signers). Only identity *results*
   in the read report remain.
3. Wasm lags Neon in two places (timestamp, OCSP), both glue.
4. JS-side follow-ups: OCSP policy, TSA override, content-based format
   detection, and mapping facade `ps256`/`timeAuthorityUrl` (still rejected on
   purpose).

## Caveats

- The facade (`compat.mjs`) still rejects `ps256` and `timeAuthorityUrl`.
- Reader `now` must be near the present for freshly generated certificates.
- Browser Wasm paths for the glue gaps were verified from the Wasm module
  loaded in Node, not in a browser.
