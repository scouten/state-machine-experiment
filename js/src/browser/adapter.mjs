/**
 * The Wasm session adapter: wraps the Wasm `ReadSession`/`BuildSession` in the
 * shape the shared drive loops expect. Separate from the Worker entry point so
 * it can also be driven from Node (tests).
 */

/**
 * @param {{ReadSession: Function, BuildSession: Function, detectFormat: Function, detectWindow: Function}} wasm Initialized module.
 * @param {{binary?: boolean}} [options] `binary: false` keeps the JSON write
 *   control used by the boundary experiment.
 */
export function createWasmAdapter({ ReadSession, BuildSession, detectFormat, detectWindow }, { binary = true } = {}) {
  return {
    /** Bytes of an asset's head that `detect` wants. */
    detectWindow: () => detectWindow(),
    /** Format (MIME type) Rust recognizes from `header`; throws if none. */
    detect: (header) => detectFormat(header),
    /** Read session for an asset of `format` (MIME type or extension). */
    create(settings, format) {
      const session = new ReadSession(format, settings);
      return {
        advance() {
          const step = JSON.parse(session.advance());
          for (const request of step.requests ?? [])
            if (request.requestDer) request.requestDer = new Uint8Array(request.requestDer);
          return step;
        },
        fulfill(id, kind, value) {
          if (kind === "bytes") session.bytes(id, value);
          else if (kind === "length") session.length(id, value);
          else if (kind === "time") session.time(id, value);
          else if (kind === "ocsp") session.ocsp(id, value);
          else if (kind === "failed") session.failed(id, value);
          else throw new Error(`unsupported reply: ${kind}`);
        },
        finish: () => session.finish(),
        close: () => session.free(),
      };
    },
    /**
     * Build session. `boundary` accumulates time spent crossing the Wasm
     * boundary (advance, JSON parse, payload copy-out) for the transport
     * experiments; it is returned with the report.
     */
    createBuild(definition, certs, alg, format, identities) {
      const bytes = (list) => list.map((cert) => Array.from(cert));
      const session = new BuildSession(definition, format, alg, JSON.stringify(bytes(certs)),
        JSON.stringify(identities.map((identity) => ({ ...identity, certs: bytes(identity.certs) }))));
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
            if (request.request) request.request = new Uint8Array(request.request);
          }
          boundary.payloadMs += performance.now() - started;
          return step;
        },
        fulfill(id, kind, value) {
          if (kind === "bytes") session.bytes(id, value);
          else if (kind === "length") session.length(id, value);
          else if (kind === "written") session.written(id);
          else if (kind === "signature") session.signature(id, value);
          else if (kind === "timestampResponse") session.timestamp_response(id, value);
          else if (kind === "failed") session.failed(id, value);
          else throw new Error(`unsupported build reply: ${kind}`);
        },
        finish() {
          const report = JSON.parse(session.finish());
          return { ...report, manifest: new Uint8Array(report.manifest), boundary };
        },
        close: () => session.free(),
      };
    },
  };
}
