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
| Sign PS256 / PS384 / PS512 | fail | rust | bridge `BuildSessionBridge::new` has no RSA signature-length parameter; Rust demands `rsa_signature_len` |
| Wasm signing algorithm choice | ES256 only | glue | `BuildSession(definition, certs)` hard-codes `"es256"`, `"image/jpeg"` |
| Timestamps, Node | pass | — | fake TSA saw the POST; token in manifest |
| Timestamps, Wasm | fail | glue | `advance` rejects Timestamp; no reply method |
| Timestamp URL/transport override | missing | js | the older standalone Neon host allowed it; Worker uses `fetch` only |
| Custom trust anchors | pass | — | `Trusted` with anchor, `Valid` without |
| TIFF read/sign (Neon, Wasm) | `UnsupportedType` | rust | bridge `for_format` knows only JPEG |
| Format detection in Node host | none | js | non-JPEG bytes reach the JPEG handler |
| Live OCSP read, Node | fail | js | "unsupported host request: ocsp"; needs an SSRF policy (older addon has `ocspPolicy`) |
| Live OCSP read, Wasm | fail | glue | `ReadSession.advance` errors "outside this offline proof" |
| CAWG identity signing | fail | rust | `Definition` is `deny_unknown_fields`; `SignPurpose` not on the wire; bridge never sets `identities` |
| CAWG identity reading | unverified | rust | no identity-bearing asset can be produced from JS |

## Findings

1. Roughly half of the apparent gaps were JS-only and are now closed; the
   algorithm guard was the largest single one.
2. The remaining blockers sit in the neutral bridge (TIFF, RSA length,
   identities) — the bridge exposes a baseline slice of what the Rust crates
   already do. Closing them needs a bridge change, not JS work.
3. Wasm lags Neon in three places (algorithm, timestamp, OCSP), all glue.
4. JS-side follow-ups: OCSP policy, TSA override, content-based format
   detection, and mapping facade `ps256`/`timeAuthorityUrl` (still rejected on
   purpose).

## Caveats

- The facade (`compat.mjs`) still rejects `ps256` and `timeAuthorityUrl`.
- Reader `now` must be near the present for freshly generated certificates.
- Browser Wasm paths for the glue gaps were verified from the Wasm module
  loaded in Node, not in a browser.
