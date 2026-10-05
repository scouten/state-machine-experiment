# 7. Proof and CI

A from-scratch reader/validator is only worth anything if it agrees with
the implementations people already trust. The evidence comes in layers.

```mermaid
flowchart TB
    U["Unit + property-style tests<br/>per crate"] --> RT
    RT["Round trips<br/>builder → handler → reader reads back Trusted<br/>(independent implementations of each side)"] --> CF
    CF["Conformance suite<br/>every FormatHandler,<br/>incl. type-erased AnyFormat"] --> DF
    DF["Differential tests vs real c2pa-rs<br/>c2pa-rs-compat-conformance"] --> CORP
    CORP["compare_corpus example<br/>whole directory of assets"]
```

* **Round trip.** The builder's primary correctness proof is that
  `contentauth-c2pa-reader` — written independently — reads what it
  builds as `Trusted`. Tamper tests flip image bytes or the rewritten TIFF
  pointer and expect failure.
* **Conformance kit.** `test_util::conformance::run_all` is what a new
  format handler must pass.
* **Differential testing against c2pa-rs.** A separate workspace (so the
  heavy `c2pa` crate doesn't burden this one's Wasm/MSRV/`cargo-deny`
  checks): the same client code reads a file through c2pa-rs and through
  `rs-compat` and compares. Both directions for TIFF — c2pa-rs-signed read
  here, and signed here read by c2pa-rs. This is what exposed the
  exclusions bug.
* **Corpus runner.** `compare_corpus` walks a directory (e.g. a checkout of
  c2pa-org's `public-testfiles`) and reports every disagreement. It has not
  yet been pointed at a large corpus — see [future](09-future.md).

## CI

`.github/workflows/ci.yml`, as separate jobs: unit tests + Codecov, doc
tests, Clippy (`-Dwarnings`), nightly rustfmt, rustdoc (warnings denied),
Wasm checks, MSRV (1.88.0), `cargo-deny`; plus separate jobs for the two
Neon addons (`node-addon`, `node-sign-addon`).

```mermaid
flowchart LR
    PR[PR to main] --> T[tests + coverage]
    PR --> L["clippy / fmt / docs"]
    PR --> W["wasm32-unknown-unknown<br/>wasm32-wasip2"]
    PR --> M[MSRV 1.88]
    PR --> D[cargo-deny]
    PR --> N["node-addon,<br/>node-sign-addon"]
```

The Wasm checks are a design assertion: **the engine and everything over it
builds for Wasm unmodified**. Exempt: `rs-compat` and `rs-compat-sign`,
which deliberately own the workspace's only network dependencies. The `web`
modules are only *compiled*, not run — there is no browser in CI.

**Next:** [Findings →](08-findings.md)
