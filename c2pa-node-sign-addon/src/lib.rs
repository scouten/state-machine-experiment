// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

//! The Neon binding: four synchronous functions, nothing else — and, as
//! in the reader addon, no `Channel`, no `Deferred`, no thread. The signing
//! key never enters this module: a `sign` request is handed to JavaScript
//! like any other, and the signature comes back through `buildFulfill`.

use std::cell::RefCell;

use contentauth_c2pa_node_compat_sign::{Error, NodeBuildSession, PendingRequest, Reply, Step};
use neon::{prelude::*, types::buffer::TypedArray};

/// A session handle JS holds. `RefCell` because Neon hands out `&self`;
/// JS is single-threaded, so it is never contended.
struct Session(RefCell<Option<NodeBuildSession>>);

impl Finalize for Session {}

fn js_error<'a>(cx: &mut impl Context<'a>, err: &Error) -> JsResult<'a, JsError> {
    // `name` carries the error-string contract, e.g. `C2pa(UnsupportedType)`.
    let js = cx.error(err.to_string())?;
    let name = cx.string(err.js_message());
    js.set(cx, "name", name)?;
    Ok(js)
}

/// `buildNew(definitionJson, format, alg, certs: Buffer[])`.
fn build_new(mut cx: FunctionContext) -> JsResult<JsBox<Session>> {
    let definition = cx.argument::<JsString>(0)?.value(&mut cx);
    let format = cx.argument::<JsString>(1)?.value(&mut cx);
    let alg = cx.argument::<JsString>(2)?.value(&mut cx);
    let list = cx.argument::<JsArray>(3)?.to_vec(&mut cx)?;
    let mut certs = Vec::with_capacity(list.len());
    for item in list {
        let buffer = item.downcast_or_throw::<JsBuffer, _>(&mut cx)?;
        certs.push(buffer.as_slice(&cx).to_vec());
    }

    match NodeBuildSession::new(&definition, &format, &alg, certs) {
        Ok(session) => Ok(cx.boxed(Session(RefCell::new(Some(session))))),
        Err(err) => {
            let js = js_error(&mut cx, &err)?;
            cx.throw(js)
        }
    }
}

/// `{ done: true }` or `{ done: false, requests: [{ id, kind, ... }] }`.
fn build_advance(mut cx: FunctionContext) -> JsResult<JsObject> {
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
                    PendingRequest::Read {
                        stream, start, len, ..
                    } => {
                        let kind = cx.string("read");
                        let stream = cx.string(stream.as_str());
                        let start = cx.number(*start as f64);
                        let len = cx.number(*len as f64);
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "stream", stream)?;
                        obj.set(&mut cx, "start", start)?;
                        obj.set(&mut cx, "len", len)?;
                    }
                    PendingRequest::Length { stream, .. } => {
                        let kind = cx.string("length");
                        let stream = cx.string(stream.as_str());
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "stream", stream)?;
                    }
                    PendingRequest::Write {
                        stream,
                        offset,
                        bytes,
                        ..
                    } => {
                        let kind = cx.string("write");
                        let stream = cx.string(stream.as_str());
                        let offset = cx.number(*offset as f64);
                        let bytes = JsBuffer::from_slice(&mut cx, bytes)?;
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "stream", stream)?;
                        obj.set(&mut cx, "offset", offset)?;
                        obj.set(&mut cx, "bytes", bytes)?;
                    }
                    PendingRequest::Sign { alg, data, .. } => {
                        let kind = cx.string("sign");
                        let alg = cx.string(alg);
                        let data = JsBuffer::from_slice(&mut cx, data)?;
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "alg", alg)?;
                        obj.set(&mut cx, "data", data)?;
                    }
                    PendingRequest::Timestamp { url, request, .. } => {
                        let kind = cx.string("timestamp");
                        let url = cx.string(url);
                        let request = JsBuffer::from_slice(&mut cx, request)?;
                        obj.set(&mut cx, "kind", kind)?;
                        obj.set(&mut cx, "url", url)?;
                        obj.set(&mut cx, "request", request)?;
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

/// `buildFulfill(session, id, kind, value)` where `kind` is
/// `bytes | length | written | signature | failed`.
fn build_fulfill(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let handle = cx.argument::<JsBox<Session>>(0)?;
    let id = cx.argument::<JsNumber>(1)?.value(&mut cx) as u64;
    let kind = cx.argument::<JsString>(2)?.value(&mut cx);

    let reply = match kind.as_str() {
        "bytes" => Reply::Bytes(cx.argument::<JsBuffer>(3)?.as_slice(&cx).to_vec()),
        "signature" => Reply::Signature(cx.argument::<JsBuffer>(3)?.as_slice(&cx).to_vec()),
        "timestampResponse" => {
            Reply::TimestampResponse(cx.argument::<JsBuffer>(3)?.as_slice(&cx).to_vec())
        }
        "length" => Reply::Length(cx.argument::<JsNumber>(3)?.value(&mut cx) as u64),
        "written" => Reply::Written,
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

/// `{ manifest: Buffer, manifestStart, manifestLen }`.
fn build_finish(mut cx: FunctionContext) -> JsResult<JsObject> {
    let handle = cx.argument::<JsBox<Session>>(0)?;
    let Some(session) = handle.0.borrow_mut().take() else {
        return cx.throw_error("session already finished");
    };
    match session.finish() {
        Ok(report) => {
            let out = cx.empty_object();
            let manifest = JsBuffer::from_slice(&mut cx, &report.manifest)?;
            let start = cx.number(report.manifest_start as f64);
            let len = cx.number(report.manifest_len as f64);
            out.set(&mut cx, "manifest", manifest)?;
            out.set(&mut cx, "manifestStart", start)?;
            out.set(&mut cx, "manifestLen", len)?;
            Ok(out)
        }
        Err(err) => {
            let js = js_error(&mut cx, &err)?;
            cx.throw(js)
        }
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("buildNew", build_new)?;
    cx.export_function("buildAdvance", build_advance)?;
    cx.export_function("buildFulfill", build_fulfill)?;
    cx.export_function("buildFinish", build_finish)?;
    Ok(())
}
