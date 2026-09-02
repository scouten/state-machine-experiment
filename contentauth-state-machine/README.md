# contentauth-state-machine

A reusable engine for building synchronous, sans-I/O state machines: a
session type that runs entirely synchronously and externalizes anything that
might need to be asynchronous (I/O, the network, a clock, signing) to its
host through an explicit request/reply protocol, rather than blocking or
spawning.

This crate carries no C2PA-specific logic. It distills the session shape
into pieces — a request/reply vocabulary trait, request tracking, a
protocol-error vocabulary, and the `advance` / `fulfill` / `finish`
interaction contract — that any subcomponent of a larger workflow can build
on independently. Concrete C2PA workflows (reading and validating a
manifest store, generating and signing one, and so on) are expected to live
in their own crates built on top of this one.

## Interaction contract

A session never blocks: when it cannot make further progress on its own, it
parks itself and reports the operations it needs its host to perform. The
host services them — concurrently and in any order, if it likes — and
reports each outcome back. Calling `advance` again lets the session consume
whatever outcomes have arrived and make further progress.

```text
             ┌────────────────────────────────────────────────┐
             │                      HOST                      │
             │   owns files, the network, keys, the clock,    │
             │            and all async scheduling            │
             └────┬───────────────────────▲───────────────────┘
        advance() │                       │ fulfill(id, reply)
                  ▼                       │
             ┌────────────────────────────────────────────────┐
             │                    SESSION                     │
             │  synchronous state machine + request tracker   │
             └────────────────────────────────────────────────┘
```

1. Create the session.
2. Call `advance`. It returns `Step::AwaitHost` when blocked on the host, or
   `Step::Complete` once the workflow has finished.
3. While `AwaitHost`: service any subset of `outstanding_requests` and
   report each outcome via `fulfill`, then call `advance` again. Outcomes
   may be reported in any order.
4. On `Complete`: consume the session with `finish` to obtain its result.

See the `Session` trait and `SessionCore` in [`src/session.rs`](src/session.rs)
for the concrete API.

## Building

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

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.
