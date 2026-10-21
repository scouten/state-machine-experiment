// Test-only Wasm adapter for the direct Blob-piece storage experiment.
import init, { ReadSession, BuildSession } from "../generated/contentauth_c2pa_wasm.js";
await init();
export const adapter = {
  create(settings) {
    const session = new ReadSession("image/jpeg", settings);
    return {
      advance: () => JSON.parse(session.advance()),
      fulfill(id, kind, value) { session[kind](id, value) },
      finish: () => session.finish(),
      close: () => session.free(),
    };
  },
  createBuild(definition, certs) {
    const session = new BuildSession(definition, JSON.stringify(certs.map((cert) => Array.from(cert))));
    return {
      advance() {
        const step = JSON.parse(session.advance(true));
        for (const request of step.requests ?? []) {
          if (request.kind === "write") request.bytes = session.payload(request.payload);
          if (request.data) request.data = new Uint8Array(request.data);
        }
        return step;
      },
      fulfill(id, kind, value) { session[kind](id, value) },
      finish() {
        const result = JSON.parse(session.finish());
        return { ...result, manifest: new Uint8Array(result.manifest) };
      },
      close: () => session.free(),
    };
  },
};
