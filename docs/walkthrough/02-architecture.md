# 2. Architecture

About twenty crates sounds like a lot. They fall into layers, and the rule
that organizes them is: **each layer knows nothing about the ones above it,
and the reader, builder and format handlers know nothing about each other.**

## Dependency graph

Arrows point from a crate to what it depends on (workspace crates only).

```mermaid
flowchart BT
    SM["contentauth-state-machine<br/><i>engine</i>"]
    PR["c2pa-primitives<br/><i>shared vocabulary</i>"]

    RD["c2pa-reader"]
    BD["c2pa-builder"]
    FM["c2pa-format<br/><i>FormatHandler contract</i>"]

    JP["c2pa-format-jpeg"]
    TF["c2pa-format-tiff"]
    RG["c2pa-format-registry"]

    FR["c2pa-file-reader"]
    FB["c2pa-file-builder"]

    RSC["rs-compat<br/><i>c2pa-rs Reader shape</i>"]
    JSC["js-compat<br/><i>c2pa-wasm shape, async</i>"]
    NDC["node-compat<br/><i>sync NodeSession</i>"]

    SB["sign-baseline"]
    RSS["rs-compat-sign"]
    JSS["js-compat-sign"]
    NDS["node-compat-sign"]

    RD --> SM & PR
    BD --> SM & PR
    FM --> SM & PR
    JP --> FM
    TF --> FM
    RG --> FM & JP & TF
    FR --> RD & FM
    FB --> BD & FM
    RSC --> FR & RG
    JSC --> FR & JP
    NDC --> FR & JSC
    SB --> BD
    RSS --> SB & FB & JP
    JSS --> SB & FB & JSC
    NDS --> SB & FB & JSC

    classDef engine fill:#dbeafe,stroke:#2563eb,color:#000
    classDef core fill:#dcfce7,stroke:#16a34a,color:#000
    classDef fmt fill:#fef9c3,stroke:#ca8a04,color:#000
    classDef glue fill:#fae8ff,stroke:#a21caf,color:#000
    classDef bind fill:#fee2e2,stroke:#dc2626,color:#000
    class SM,PR engine
    class RD,BD core
    class FM,JP,TF,RG fmt
    class FR,FB glue
    class RSC,JSC,NDC,SB,RSS,JSS,NDS bind
```

(Edges to `primitives` and `state-machine` from most crates are omitted
where they would only add noise; every session crate depends on both.)

## Layers

```mermaid
flowchart TB
    subgraph L5["Bindings — c2pa-rs / c2pa-wasm / c2pa-node shaped APIs"]
        direction LR
        b1[rs-compat] ~~~ b2[js-compat] ~~~ b3[node-compat] ~~~ b4["*-compat-sign"]
    end
    subgraph L4["Orchestration — compose a format with a session"]
        direction LR
        o1[file-reader] ~~~ o2[file-builder]
    end
    subgraph L3["Formats — plain-data contract + one crate per format"]
        direction LR
        f1[format] ~~~ f2[jpeg] ~~~ f3[tiff] ~~~ f4[registry]
    end
    subgraph L2["Workflows — C2PA, no container knowledge"]
        direction LR
        w1[reader] ~~~ w2[builder]
    end
    subgraph L1["Foundation — no C2PA workflow logic"]
        direction LR
        e1[state-machine] ~~~ e2[primitives]
    end
    L5 --> L4 --> L2 --> L1
    L4 --> L3 --> L1
```

## Crate table

| Crate | Layer | What it is |
|---|---|---|
| `contentauth-state-machine` | Foundation | The engine: `Session`, `SessionCore`, request tracking, protocol errors. Domain-agnostic. |
| `contentauth-c2pa-primitives` | Foundation | The narrow shared slice: `StreamId`, `ByteRange`, hash/signing algorithms, `HostError`, COSE `Sig_structure`, RFC 3161 encode/unwrap. |
| `contentauth-c2pa-reader` | Workflow | `ReadSession`: JUMBF, claims (v1+v2), integrity, signature, trust, timestamps, OCSP. |
| `contentauth-c2pa-builder` | Workflow | `BuilderSession`: v2 claim generation and signing via a two-pass placeholder scheme. |
| `contentauth-c2pa-format` | Format | `FormatHandler` trait, `FormatDescriptor`, `IoRequest`, `EmbedPlan`/`Patch`, test kit + conformance suite. |
| `…-format-jpeg` | Format | APP11 segments; byte-compatible with c2pa-rs. The template for other handlers. |
| `…-format-tiff` | Format | TIFF/BigTIFF/DNG; the format that forced `exclusions` to become a list. |
| `…-format-registry` | Format (host side) | Detect by content / extension / MIME; type-erased `AnyFormat`. |
| `…-file-reader` | Orchestration | `FileReadSession`: `locate` + `ReadSession`; plus a blocking `Read + Seek` host. |
| `…-file-builder` | Orchestration | `FileBuilderSession`: `plan_embed`/`commit` + `BuilderSession`, never buffering the asset; plus blocking hosts. |
| `…-rs-compat` | Binding | c2pa-rs `Context` + `Reader::with_file` slice; one of two crates with a network dependency (`reqwest` OCSP). |
| `…-js-compat` | Binding | c2pa-wasm `WasmReader` slice; async host with `Blob`/`Platform` traits; `web` feature for `wasm-bindgen`. |
| `…-node-compat` (+ `c2pa-node-compat-addon`) | Binding | Purely synchronous `NodeSession`; Node owns all async. Addon is a separate Neon workspace. |
| `…-sign-baseline` | Binding | The baseline signing case (JSON definition → `BuilderSettings`) every write binding is held to. |
| `…-rs/js/node-compat-sign` (+ `c2pa-node-sign-addon`) | Binding | The baseline case through each binding. `rs-compat-sign` is the other crate with a network dependency (`reqwest` for RFC 3161 timestamps). |
| `c2pa-rs-compat-conformance` | Test | Separate workspace; differential tests against the real `c2pa` crate. |

## Rules of the road

* **Reader and builder never mention a container format.** They ask for "the
  manifest store's bytes" or "embed this placeholder and report its range".
* **Formats never mention a session.** A handler speaks only `IoRequest`
  and returns plain data.
* **Only the registry names more than one format**, behind features.
* **Nothing is async below the host.** Even `js-compat`, the async one, has
  its `.await`s in a single function.
* **Lints enforce discipline:** `unsafe_code`, `missing_docs`,
  `unwrap_used`, `expect_used`, `panic` are denied at crate roots.

**Next:** [The read path →](03-read-path.md)
