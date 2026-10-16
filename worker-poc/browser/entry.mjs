import init, { ReadSession, BuildSession } from "../generated/worker_poc_wasm.js";
import { serve } from "../shared/service.mjs";

await init();
serve({
  post: (message) => self.postMessage(message),
  onMessage: (callback) => { self.onmessage = (event) => callback(event.data) },
}, {
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
  createBuild(definition, certs) {
    const session = new BuildSession(definition, JSON.stringify(certs.map((cert) => Array.from(cert))));
    return {
      advance() {
        const step = JSON.parse(session.advance());
        for (const request of step.requests ?? []) {
          if (request.bytes) request.bytes = new Uint8Array(request.bytes);
          if (request.data) request.data = new Uint8Array(request.data);
        }
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
        return { ...report, manifest: new Uint8Array(report.manifest) };
      },
      close: () => session.free(),
    };
  },
});
