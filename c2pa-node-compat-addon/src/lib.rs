// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

//! The Neon binding: five synchronous functions, nothing else.
//!
//! Compare c2pa-node's `neon_reader.rs`: a process-wide tokio runtime, a
//! `JsPromise` settled from a `Channel` on a worker thread, a
//! `Mutex<Reader>`, and `block_on` in every accessor. Here every exported
//! function takes the JS thread for the length of a bounded slice of
//! engine work and returns. No `Channel`, no `Deferred`, no `Root`, no
//! thread. All asynchrony is the JavaScript driver's (`index.mjs`).

use std::cell::RefCell;

use contentauth_c2pa_node_compat::{Error, NodeSession, PendingRequest, Reply, Step};
use neon::{prelude::*, types::buffer::TypedArray};

/// A session handle JS holds. `RefCell` because Neon hands out `&self`;
/// JS is single-threaded, so it is never contended.
struct Session(RefCell<Option<NodeSession>>);

impl Finalize for Session {}

fn js_error<'a>(cx: &mut impl Context<'a>, err: &Error) -> JsResult<'a, JsError> {
    // `name` carries the Debug string, e.g. `C2pa(JumbfNotFound)`, which
    // is c2pa-node's own error contract (`error.rs::as_js_error`).
    let js = cx.error(err.to_string())?;
    let name = cx.string(err.js_message());
    js.set(cx, "name", name)?;
    Ok(js)
}

fn session_new(mut cx: FunctionContext) -> JsResult<JsBox<Session>> {
    let format = cx.argument::<JsString>(0)?.value(&mut cx);
    let settings = cx
        .argument_opt(1)
        .filter(|v| v.is_a::<JsString, _>(&mut cx))
        .map(|v| v.downcast_or_throw::<JsString, _>(&mut cx))
        .transpose()?
        .map(|s| s.value(&mut cx));

    match NodeSession::new(&format, settings.as_deref()) {
        Ok(session) => Ok(cx.boxed(Session(RefCell::new(Some(session))))),
        Err(err) => {
            let js = js_error(&mut cx, &err)?;
            cx.throw(js)
        }
    }
}

/// `{ done: true }` or `{ done: false, requests: [{ id, kind, ... }] }`.
fn session_advance(mut cx: FunctionContext) -> JsResult<JsObject> {
    let handle = cx.argument::<JsBox<Session>>(0)?;
    let step = match handle.0.borrow_mut().as_mut() {
        Some(session) => session.advance(),
        None => return cx.throw_error("session already finished"),
    };

    let out = cx.empty_object();
    match step {
        Err(err) => {
            let js = js_error(&mut cx, &err)?;
            cx.throw(js)
        }
        Ok(Step::Complete) => {
            let done = cx.boolean(true);
            out.set(&mut cx, "done", done)?;
            Ok(out)
        }
        Ok(Step::Pending(requests)) => {
            let done = cx.boolean(false);
            out.set(&mut cx, "done", done)?;
            let list = cx.empty_array();
            for (i, request) in requests.iter().enumerate() {
                let obj = cx.empty_object();
                let id = cx.number(request.id() as f64);
                obj.set(&mut cx, "id", id)?;
                match request {
                    PendingRequest::Read { start, len, .. } => {
                        let kind = cx.string("read");
                        let start = cx.number(*start as f64);
                        let len = cx.number(*len as f64);
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "start", start)?;
                        obj.set(&mut cx, "len", len)?;
                    }
                    PendingRequest::Length { .. } => {
                        let kind = cx.string("length");
                        obj.set(&mut cx, "kind", kind)?;
                    }
                    PendingRequest::CurrentDateTime { .. } => {
                        let kind = cx.string("time");
                        obj.set(&mut cx, "kind", kind)?;
                    }
                    PendingRequest::Ocsp {
                        url, request_der, ..
                    } => {
                        let kind = cx.string("ocsp");
                        let url = cx.string(url);
                        let der = JsBuffer::from_slice(&mut cx, request_der)?;
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "url", url)?;
                        obj.set(&mut cx, "requestDer", der)?;
                    }
                    _ => {}
                }
                list.set(&mut cx, i as u32, obj)?;
            }
            out.set(&mut cx, "requests", list)?;
            Ok(out)
        }
    }
}

/// `sessionFulfill(session, id, kind, value)` where `kind` is
/// `bytes | length | time | ocsp | failed`.
fn session_fulfill(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let handle = cx.argument::<JsBox<Session>>(0)?;
    let id = cx.argument::<JsNumber>(1)?.value(&mut cx) as u64;
    let kind = cx.argument::<JsString>(2)?.value(&mut cx);

    let reply = match kind.as_str() {
        "bytes" => Reply::Bytes(cx.argument::<JsBuffer>(3)?.as_slice(&cx).to_vec()),
        "ocsp" => Reply::Ocsp(cx.argument::<JsBuffer>(3)?.as_slice(&cx).to_vec()),
        "length" => Reply::Length(cx.argument::<JsNumber>(3)?.value(&mut cx) as u64),
        "time" => Reply::Time(cx.argument::<JsNumber>(3)?.value(&mut cx) as i64),
        "failed" => Reply::Failed(cx.argument::<JsString>(3)?.value(&mut cx)),
        other => return cx.throw_error(format!("unknown reply kind {other:?}")),
    };

    let result = match handle.0.borrow_mut().as_mut() {
        Some(session) => session.fulfill(id, reply),
        None => return cx.throw_error("session already finished"),
    };
    match result {
        Ok(()) => Ok(cx.undefined()),
        Err(err) => {
            let js = js_error(&mut cx, &err)?;
            cx.throw(js)
        }
    }
}

/// The manifest store as c2pa-rs-shaped JSON, or `null` if the asset has
/// none. (JS builds its `Reader` from this, as c2pa-node's own JS `Reader`
/// does from `readerJson`.)
fn session_finish(mut cx: FunctionContext) -> JsResult<JsValue> {
    let handle = cx.argument::<JsBox<Session>>(0)?;
    let Some(session) = handle.0.borrow_mut().take() else {
        return cx.throw_error("session already finished");
    };
    match session.finish() {
        Ok(Some(reader)) => Ok(cx.string(reader.json()).upcast()),
        Ok(None) => Ok(cx.null().upcast()),
        Err(err) => {
            let js = js_error(&mut cx, &err)?;
            cx.throw(js)
        }
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("sessionNew", session_new)?;
    cx.export_function("sessionAdvance", session_advance)?;
    cx.export_function("sessionFulfill", session_fulfill)?;
    cx.export_function("sessionFinish", session_finish)?;
    Ok(())
}
