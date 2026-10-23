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

### Threading

A session is **not re-entrant**, and the Rust code provides **no locks**
around it. Any host that employs a thread model must ensure the session's
methods are never called simultaneously from multiple threads (nor
re-entered from within a call in progress on the same session). Crashes or
unpredictable behavior are likely if this constraint is violated. Calls on
*different* sessions may safely run at the same time; only calls on the
*same* session must not. A session may also move to another thread between
calls. In safe Rust the
borrow checker does much of this for you (`advance` and `fulfill` take
`&mut self`, `finish` takes `self`), but hosts that share a session through
interior mutability or reach it through a raw-handle binding must enforce
it themselves.

See the `Session` trait and `SessionCore` in [`src/session.rs`](src/session.rs)
for the concrete API.

Synchronous hosts can use `session.respond(|request| answer(request))?`
after each `AwaitHost`. This borrows each request, obtains its owned reply,
and calls `fulfill` before servicing the next request: no request clones
or intermediate reply batch are needed. It stops on the first protocol
error, leaves earlier replies delivered, and does not call `advance`.
Host-operation failures are carried in the vocabulary's reply type.
Async hosts and hosts that service only a subset or choose another order
continue to use `outstanding_requests` / `fulfill` directly.

## Building

```sh
cargo test
```

Minimum supported Rust version: 1.96.0.

Code format uses nightly rustfmt:

```sh
rustup toolchain add nightly
cargo +nightly fmt
```

## Testing and fuzzing

The engine's bookkeeping is the one piece every session shares, so it is
tested adversarially. [`tests/support/model.rs`](tests/support/model.rs)
holds two *model-based* harnesses. Each takes a script of host calls —
including illegal ones: unknown or foreign IDs, wrong reply payloads,
replies after completion or failure — runs it against the real engine and
against a deliberately naive reference model, and asserts they agree after
every step:

* `run_core` drives `SessionCore` directly, as a workflow would;
* `run_session` drives a complete `Session` through the public
  `advance` / `fulfill` / `outstanding_requests` / `finish` contract.

Two front ends feed them:

* [`tests/model_based.rs`](tests/model_based.rs) uses
  [`proptest`](https://docs.rs/proptest) for structured, shrinking
  generation. It runs in plain `cargo test`.
* [`fuzz/`](fuzz) uses [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
  (libFuzzer) for coverage-guided generation from raw bytes. It is outside
  the workspace because it needs nightly:

  ```sh
  cargo install cargo-fuzz
  cargo +nightly fuzz run session_core        # from this directory
  cargo +nightly fuzz run fan_out_session
  ```

  CI runs each target for a short, fixed time on every PR. A crash
  artifact replays with `cargo +nightly fuzz run <target> <artifact>`;
  turn it into a named case in `seed_scripts` in `tests/model_based.rs`
  once fixed.

## License

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.
