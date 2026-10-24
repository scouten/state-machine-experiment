import init, { BuildSession } from "../generated/contentauth_c2pa_wasm.js";

function check(value, message) { if (!value) throw new Error(message) }
function throws(action, pattern) {
  try { action() }
  catch (error) { check(pattern.test(String(error)), `unexpected error: ${error}`); return }
  throw new Error("expected lease rejection");
}

export async function leaseContract(fixture) {
  const wasm = await init();
  const session = new BuildSession(JSON.stringify(fixture.signing.definition),
    JSON.stringify(fixture.signing.certs));
  const source = new Uint8Array([255, 216, 255, 217]);
  try {
    for (let turn = 0; turn < 100; turn++) {
      const step = JSON.parse(session.advance(true));
      check(!step.done, "build completed before leasing a write");
      for (const request of step.requests) {
        if (request.kind === "length") session.length(request.id, source.length);
        else if (request.kind === "read")
          session.bytes(request.id, source.subarray(request.start, request.start + request.len));
        else if (request.kind === "write") {
          const index = request.payload;
          const ptr = session.payload_ptr(index);
          check(ptr === session.payload_ptr(index), "lease moved its allocation");
          let view = new Uint8Array(wasm.memory.buffer, ptr, request.len);
          const expected = view.slice();
          throws(() => session.advance(true), /unconsumed write payload/);
          wasm.memory.grow(1);
          check(view.byteLength === 0, "memory growth did not invalidate the old buffer");
          view = new Uint8Array(wasm.memory.buffer, session.payload_ptr(index), request.len);
          check(view.every((byte, i) => byte === expected[i]), "growth changed leased bytes");
          view = undefined;
          session.release_payload(index);
          throws(() => session.payload_ptr(index), /unknown or consumed/);
          throws(() => session.release_payload(index), /unknown or consumed/);
          throws(() => session.payload(index), /unknown or consumed/);
          throws(() => session.payload_ptr(0xffff_ffff), /unknown or consumed/);
          session.written(request.id);
          // Any additional payloads in this batch are deliberately abandoned:
          // freeing the session must also release outstanding leases.
          return ["stable shared allocation", "advance blocked by live lease", "fresh view after memory.grow",
            "single release", "copied/leased access mutually exclusive", "unknown lease rejected",
            "session disposal with pending work"];
        } else throw new Error(`unexpected lease-test request: ${request.kind}`);
      }
    }
    throw new Error("no write lease issued");
  } finally { session.free() }
}
