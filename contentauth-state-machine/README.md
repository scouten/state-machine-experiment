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

## Debugging a session

A state machine that stops with an error can be hard to diagnose: by the
time the host sees the error, the session has moved on (or poisoned
itself), and the call stack that produced it is gone. Two things answer
"where did it go wrong, and why?":

* **Where it is, and where it failed.** `Session::phase` describes the
  session's current phase in words — `"Locating > Scanning > Marker at
  byte 2"`, `"Building > AwaitingSignature"` — with a session nested inside
  another named after the outer phase. A failed session keeps reporting the
  phase it failed in, and every later call returns
  `ProtocolError::SessionFailed(Failure)`, which carries that phase and the
  original error's text rather than a bare "failed earlier". A session
  implementation records both with `SessionCore::mark_failed(phase, &err)`
  on every error exit (only the first failure is kept). Phase wording is
  for people and logs, not a stable interface: don't branch on it.
* **What the host said to it.** Since a session performs no I/O, its
  behavior depends on nothing but the replies it is given. Wrap a session
  in a `Recorder` — itself a `Session`, so the host does not change — and
  it keeps a `Transcript` of every `advance` (the phase, what it returned,
  the requests it issued) and every `fulfill` (the reply, and whether it
  was accepted). A transcript prints as a readable one-line-per-call log,
  and `replay` drives a fresh session through it, reproducing the run
  exactly — on another machine, under a debugger, or against a fix — or
  reporting the first call where the session behaved differently
  (`Divergence`). A transcript holds every reply in full, asset bytes
  included, so record only where its size and contents are acceptable.

```rust,ignore
let mut session = Recorder::new(FileReadSession::new(&handler, settings));
// ...drive `session` exactly as before...
if let Err(err) = session.advance() {
    eprintln!("failed in {}: {err}\n{}", session.phase(), session.transcript());
}
```

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
