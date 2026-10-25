/**
 * Browser Worker entry point: wraps the Wasm `ReadSession`/`BuildSession`
 * in the adapter shape `serve()` expects (see shared/service.mjs).
 * Loaded as a module Worker by browser/client.mjs.
 */
import init, { ReadSession, BuildSession } from "../../generated/contentauth_c2pa_wasm.js";
import { serve } from "../shared/service.mjs";

const wasm = await init();
// Copied binary and JSON controls are retained only for the boundary experiment.
const transport = new URL(self.location.href).searchParams.get("transport") ?? "leased";
const binary = transport !== "json";
const leased = transport === "leased";
serve({
  post: (message) => self.postMessage(message),
  onMessage: (callback) => { self.onmessage = (event) => callback(event.data) },
}, {
  /** Read session; the Wasm glue handles JPEG only, so the format is fixed. */
  create(settings) {
    const session = new ReadSession("image/jpeg", settings);
    return {
      advance: () => JSON.parse(session.advance()),
      fulfill(id, kind, value) {
        if (kind === "bytes") session.bytes(id, value);
        else if (kind === "length") session.length(id, value);
        else if (kind === "time") session.time(id, value);
        else throw new Error(`unsupported reply: ${kind}`);
      },
      finish: () => session.finish(),
      close: () => session.free(),
    };
  },
  /**
   * Build session (ES256 JPEG only). `boundary` accumulates time spent
   * crossing the Wasm boundary (advance, JSON parse, payload copy-out) for
   * the transport experiments; it is returned with the report.
   */
  createBuild(definition, certs) {
    const session = new BuildSession(definition, JSON.stringify(certs.map((cert) => Array.from(cert))));
    const boundary = { transport, wasmAdvanceMs: 0, parseMs: 0,
      payloadMs: 0, metadataChars: 0, writePayloadBytes: 0, copiedPayloadBytes: 0, writes: 0 };
    return {
      advance() {
        let started = performance.now();
        const json = session.advance(binary);
        boundary.wasmAdvanceMs += performance.now() - started;
        boundary.metadataChars += json.length;
        started = performance.now();
        const step = JSON.parse(json);
        boundary.parseMs += performance.now() - started;
        started = performance.now();
        for (const request of step.requests ?? []) {
          if (request.kind === "write") {
            if (!leased) {
              request.bytes = binary ? session.payload(request.payload) : new Uint8Array(request.bytes);
              request.len = request.bytes.length;
              boundary.copiedPayloadBytes += request.len;
            }
            boundary.writes++;
            boundary.writePayloadBytes += request.len;
          }
          if (request.data) request.data = new Uint8Array(request.data);
        }
        boundary.payloadMs += performance.now() - started;
        return step;
      },
      write(request, output) {
        const started = performance.now();
        if (leased) {
          const ptr = session.payload_ptr(request.payload);
          // No await or Wasm call while the view exists. memory.grow can detach
          // an earlier buffer, so acquire memory.buffer anew for every write.
          output.set(new Uint8Array(wasm.memory.buffer, ptr, request.len), request.offset);
          session.release_payload(request.payload);
        } else {
          output.set(request.bytes, request.offset);
        }
        boundary.payloadMs += performance.now() - started;
      },
      fulfill(id, kind, value) {
        if (kind === "bytes") session.bytes(id, value);
        else if (kind === "length") session.length(id, value);
        else if (kind === "written") session.written(id);
        else if (kind === "signature") session.signature(id, value);
        else throw new Error(`unsupported build reply: ${kind}`);
      },
      finish() {
        const report = JSON.parse(session.finish());
        return { ...report, manifest: new Uint8Array(report.manifest), boundary };
      },
      close: () => session.free(),
    };
  },
});
