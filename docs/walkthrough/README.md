# Walkthrough: sans-I/O state machines for C2PA

A guided tour of this repository for teammates. It is written to be read
(or presented) on GitHub — every diagram is [Mermaid](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams),
which GitHub renders inline, in the browser and in GitHub Desktop's preview.

> **Status: very experimental.** Nothing here has a compatibility guarantee.
> The point of the repo is to find out whether this architecture is a good
> one, not to ship it.

## The one-sentence version

A C2PA reader and builder written as **pure, synchronous state machines
that never do I/O** — where c2pa-rs's `Reader`/`Builder` pull bytes, the
clock, and the network themselves, these *ask their host* and carry on when
the answer arrives — so one engine can sit under a blocking Rust API, an
`async` Wasm API, and a Node addon, each host choosing its own asynchrony.

**Audience assumption:** you already know the c2pa-rs SDK and its language
bindings. [Page 1](01-the-idea.md) is a direct comparison with them.

## Reading order

| # | Page | Time | Question it answers |
|---|---|---|---|
| 1 | [The idea vs. c2pa-rs](01-the-idea.md) | 6 min | What is structurally different from c2pa-rs and its bindings? |
| 2 | [Architecture](02-architecture.md) | 5 min | What are all these crates and how do they depend on each other? |
| 3 | [The read path](03-read-path.md) | 8 min | How does a manifest get read and validated? |
| 4 | [The write path](04-write-path.md) | 8 min | How do we sign a manifest into a file whose layout we don't know yet? |
| 5 | [Container formats](05-formats.md) | 8 min | How do JPEG and TIFF plug in, and what did TIFF teach us? |
| 6 | [Bindings](06-bindings.md) | 8 min | The same engine behind c2pa-rs, c2pa-wasm, and c2pa-node-shaped APIs |
| 7 | [Proof and CI](07-proof-and-ci.md) | 4 min | Why should we believe it works? |
| 8 | [Findings](08-findings.md) | 5 min | What did building this teach us? |
| 9 | [Future directions](09-future.md) | 6 min | Where could this go next? |

About an hour with discussion. For a 15-minute version, present pages 1, 2,
6 and 9.

## Where the detail lives

These pages are a map, not the territory. The authoritative detail is in:

* [`CLAUDE.md`](../../CLAUDE.md) — the full crate-by-crate description.
* Each crate's own `README.md` and rustdoc.
* [`reference/c2pa-spec`](../../reference/c2pa-spec) — a pinned snapshot of
  the C2PA specification (2.4) the code is written against.

## Keeping this current

This walkthrough is maintained alongside the code (see
[`CLAUDE.md`](../../CLAUDE.md)). A PR that adds a crate, changes how crates
relate, lands a roadmap item from [Future directions](09-future.md), or
changes what the engine validates should update the affected pages — in
particular the crate table and dependency graph in
[Architecture](02-architecture.md), and the "done" / "next" split in
[Future directions](09-future.md). When a diagram and the code disagree, the
code wins; fix the diagram.
