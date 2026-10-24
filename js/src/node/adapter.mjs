/**
 * Node session adapter over the two Neon addons (reader and signer).
 * Same shape as the Wasm adapter in browser/entry.mjs, so the shared drive
 * loops run unchanged. Neon needs `Buffer`s, so Uint8Array replies are
 * wrapped here (a view for `bytes`, a copy for the small signer inputs).
 */
import { createRequire } from "node:module";

const native = createRequire(import.meta.url)("../../../c2pa-node-compat-addon/index.node");
const signing = createRequire(import.meta.url)("../../../c2pa-node-sign-addon/index.node");
/** Session factory (`create`, `createBuild`) the shared Worker service drives. */
export const adapter = {
  /** Read session. The addon only knows JPEG. */
  create(settings) {
    let session = native.sessionNew("image/jpeg", settings);
    return {
      advance: () => native.sessionAdvance(session),
      fulfill: (id, kind, value) => native.sessionFulfill(session, id, kind,
        kind === "bytes" ? Buffer.from(value.buffer, value.byteOffset, value.byteLength) : value),
      finish: () => native.sessionFinish(session),
      close() { session = undefined }, // Native errors release the handle through isolate GC.
    };
  },
  /** Build session (ES256 JPEG only in this slice). */
  createBuild(definition, certs) {
    let session = signing.buildNew(definition, "image/jpeg", "es256", certs.map((cert) => Buffer.from(cert)));
    return {
      advance() {
        const step = signing.buildAdvance(session);
        for (const request of step.requests ?? []) {
          if (request.kind === "write") request.len = request.bytes.length;
        }
        return step;
      },
      write(request, output) { output.set(request.bytes, request.offset) },
      fulfill: (id, kind, value) => signing.buildFulfill(session, id, kind,
        kind === "bytes" || kind === "signature" ? Buffer.from(value) : value),
      finish: () => signing.buildFinish(session),
      close() { session = undefined },
    };
  },
};
