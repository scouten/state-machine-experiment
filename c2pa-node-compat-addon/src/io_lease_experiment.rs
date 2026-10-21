// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

//! Test-only ownership/copy probes, not a session lease API.
//! The external buffer exclusively owns its Vec until Neon's GC finalizer.
//! Rust retains only counters and address strings, never aliases to that Vec.

#![forbid(unsafe_code)]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use contentauth_c2pa_session_bridge::Bytes;
use neon::{prelude::*, types::buffer::TypedArray};

struct Allocation {
    data: Vec<u8>,
    finalized: Arc<AtomicUsize>,
}

impl AsMut<[u8]> for Allocation {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        self.finalized.fetch_add(1, Ordering::SeqCst);
    }
}

struct Tracker(Arc<AtomicUsize>);
impl Finalize for Tracker {}

struct Snapshot(Bytes);
impl Finalize for Snapshot {}

fn length(cx: &mut FunctionContext, index: usize, limit: usize) -> NeonResult<usize> {
    let value = cx.argument::<JsNumber>(index)?.value(cx);
    if !value.is_finite() || value.fract() != 0.0 || value < 0.0 || value > limit as f64 {
        return cx.throw_range_error("length must be an integer within the buffer limit");
    }
    Ok(value as usize)
}

fn external<'a>(
    cx: &mut FunctionContext<'a>,
    data: Vec<u8>,
    copied_bytes: usize,
) -> JsResult<'a, JsObject> {
    let address = format!("{:p}", data.as_ptr());
    let finalized = Arc::new(AtomicUsize::new(0));
    let tracker = cx.boxed(Tracker(Arc::clone(&finalized)));
    let buffer = JsBuffer::external(cx, Allocation { data, finalized });
    let view_address = format!("{:p}", buffer.as_slice(cx).as_ptr());
    let result = cx.empty_object();
    let address = cx.string(address);
    let view_address = cx.string(view_address);
    let copied_bytes = cx.number(copied_bytes as f64);
    result.set(cx, "buffer", buffer)?;
    result.set(cx, "tracker", tracker)?;
    result.set(cx, "allocationPointer", address)?;
    result.set(cx, "viewPointer", view_address)?;
    result.set(cx, "copiedBytes", copied_bytes)?;
    Ok(result)
}

fn allocate(mut cx: FunctionContext) -> JsResult<JsObject> {
    let len = length(&mut cx, 0, 16 * 1024 * 1024)?;
    if len == 0 {
        return cx.throw_range_error("use a nonempty allocation for pointer evidence");
    }
    external(&mut cx, vec![0; len], 0)
}

fn pointer(mut cx: FunctionContext) -> JsResult<JsString> {
    let buffer = cx.argument::<JsBuffer>(0)?;
    let address = format!("{:p}", buffer.as_slice(&cx).as_ptr());
    Ok(cx.string(address))
}

fn finalized(mut cx: FunctionContext) -> JsResult<JsNumber> {
    let tracker = cx.argument::<JsBox<Tracker>>(0)?;
    Ok(cx.number(tracker.0.load(Ordering::SeqCst) as f64))
}

fn copy_in(mut cx: FunctionContext) -> JsResult<JsObject> {
    let buffer = cx.argument::<JsBuffer>(0)?;
    let limit = buffer.as_slice(&cx).len();
    let len = length(&mut cx, 1, limit)?;
    if len == 0 {
        return cx.throw_range_error("use a nonempty snapshot for pointer evidence");
    }
    let source = &buffer.as_slice(&cx)[..len];
    let source_address = format!("{:p}", source.as_ptr());
    // This is the production read boundary's required copy, not a seal.
    let copied = source.to_vec();
    let vec_address = format!("{:p}", copied.as_ptr());
    let data = Bytes::from(copied);
    let address = format!("{:p}", data.as_ptr());
    let result = cx.empty_object();
    let snapshot = cx.boxed(Snapshot(data));
    let address = cx.string(address);
    let vec_address = cx.string(vec_address);
    let source_address = cx.string(source_address);
    let copied_bytes = cx.number(len as f64);
    result.set(&mut cx, "bytes", snapshot)?;
    result.set(&mut cx, "allocationPointer", address)?;
    result.set(&mut cx, "vecPointer", vec_address)?;
    result.set(&mut cx, "sourcePointer", source_address)?;
    result.set(&mut cx, "copiedBytes", copied_bytes)?;
    Ok(result)
}

fn copy_out(mut cx: FunctionContext) -> JsResult<JsObject> {
    let snapshot = cx.argument::<JsBox<Snapshot>>(0)?;
    let source_address = format!("{:p}", snapshot.0.as_ptr());
    // Bytes cannot satisfy JsBuffer::external's AsMut<[u8]> bound. Copy to a
    // uniquely owned Vec instead; never implement AsMut over immutable Bytes.
    let result = external(&mut cx, snapshot.0.to_vec(), snapshot.0.len())?;
    let source_address = cx.string(source_address);
    result.set(&mut cx, "sourcePointer", source_address)?;
    Ok(result)
}

fn observe(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let snapshot = cx.argument::<JsBox<Snapshot>>(0)?;
    // Observation itself copies; not included in the I/O boundary counters.
    JsBuffer::from_slice(&mut cx, &snapshot.0)
}

pub(super) fn register(cx: &mut ModuleContext) -> NeonResult<()> {
    cx.export_function("leaseProbeAllocate", allocate)?;
    cx.export_function("leaseProbePointer", pointer)?;
    cx.export_function("leaseProbeFinalized", finalized)?;
    cx.export_function("leaseProbeCopyIn", copy_in)?;
    cx.export_function("leaseProbeCopyOut", copy_out)?;
    cx.export_function("leaseProbeObserve", observe)?;
    Ok(())
}
