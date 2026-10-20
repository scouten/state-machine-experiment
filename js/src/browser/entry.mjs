/**
 * Browser Worker entry point: wraps the Wasm `ReadSession`/`BuildSession`
 * in the adapter shape `serve()` expects (see shared/service.mjs).
 * Loaded as a module Worker by browser/client.mjs.
 */
import init, { ReadSession, BuildSession } from "../../generated/contentauth_c2pa_wasm.js";
import { serve } from "../shared/service.mjs";

await init();
// The JSON control is retained only for the boundary experiment.
const binary = new URL(self.location.href).searchParams.get("transport") !== "json";
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
    const boundary = { transport: binary ? "binary" : "json", wasmAdvanceMs: 0, parseMs: 0,
      payloadMs: 0, metadataChars: 0, writePayloadBytes: 0, writes: 0 };
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
          // Binary transport: write bytes stay in Wasm memory and are copied
          // out once by `payload`; JSON transport inlines them as number arrays.
          if (request.kind === "write") {
            request.bytes = binary ? session.payload(request.payload) : new Uint8Array(request.bytes);
            delete request.payload;
            boundary.writes++;
            boundary.writePayloadBytes += request.bytes.length;
          }
          if (request.data) request.data = new Uint8Array(request.data);
        }
        boundary.payloadMs += performance.now() - started;
        return step;
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
