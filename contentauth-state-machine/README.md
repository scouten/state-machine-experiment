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

## Two ways to implement a session

The host-facing contract above is fixed. Behind it, a session's own
workflow can be written either of two ways, and the host cannot tell which:

* **By hand, with `SessionCore`** ([`src/session.rs`](src/session.rs)). The
  workflow keeps a phase enum with one variant per point where it waits on
  its host, each carrying every local that must survive the wait, and
  `advance` matches on it. Every state is explicit and inspectable — and
  every new wait costs a variant, a handler, and the same
  `None` / `Failed` / wrong-reply arms again.
  `contentauth-c2pa-reader`'s `ReadSession` and
  `contentauth-c2pa-builder`'s `BuilderSession` use this approach.
* **As an `async fn`, with `Workflow`** ([`src/workflow.rs`](src/workflow.rs)).
  The workflow asks its `Host` handle for what it needs and `.await`s the
  reply; the compiler generates the state machine, including the locals,
  loops, `?` early returns and sub-workflow calls a hand-written one would
  have to encode. `advance` polls the future once with a no-op waker —
  there is no executor, runtime, or thread, and nothing to wake, because a
  `PendingReply` is ready exactly when `fulfill` has delivered its reply.
  Issuing several requests before awaiting any puts them in front of the
  host at once. The reader's experimental `read_workflow` is an example;
  it is available behind that crate's `engine` feature.

The trade: a `Workflow`'s position is opaque — a test observes it as a host
does, through `outstanding_requests`, rather than by matching on a phase
enum — and it must await only `PendingReply`s (or futures built from them).
Awaiting anything else would never be woken; `advance` reports that as
`ProtocolError::WorkflowStalled` instead of hanging.

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

## License

Licensed under either the [Apache License, Version 2.0](../LICENSE-APACHE) or
the [MIT license](../LICENSE-MIT), at your option.
