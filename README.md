# state-machine-experiment

A suite of prototypes exploring synchronous, sans-I/O state machines for
C2PA workflows.

The foundation is [`contentauth-state-machine`](contentauth-state-machine),
a reusable engine for building sessions that never block: a session runs
entirely synchronously and externalizes anything that might need to be
asynchronous (I/O, the network, a clock, signing) to its host through an
explicit request/reply protocol, rather than blocking or spawning. It
carries no C2PA-specific logic of its own — it just distills the session
shape (a request/reply vocabulary trait, request tracking, a protocol-error
vocabulary, and the `advance` / `fulfill` / `finish` interaction contract)
into pieces any subcomponent of a larger workflow can build on
independently.

Concrete C2PA workflows built on top of that engine — reading and
validating a manifest store, generating and signing one, and so on — are
expected to live in their own crates alongside it in this workspace as the
experiment grows.

## Crates

* [`contentauth-state-machine`](contentauth-state-machine) — the
  sans-I/O session engine. See its
  [README](contentauth-state-machine/README.md) for the interaction
  contract and build instructions.
* [`contentauth-c2pa-reader`](contentauth-c2pa-reader) — reads and
  validates C2PA manifest stores, built on top of the engine above. See its
  [README](contentauth-c2pa-reader/README.md) for what it validates and its
  request vocabulary.

## Building

This repo is a Cargo workspace; the usual commands run across all members
from the repository root:

```sh
cargo test
```

Minimum supported Rust version: 1.88.0.

Code format uses nightly rustfmt:

```sh
rustup toolchain add nightly
cargo +nightly fmt
```

## License

Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or
the [MIT license](LICENSE-MIT), at your option.
