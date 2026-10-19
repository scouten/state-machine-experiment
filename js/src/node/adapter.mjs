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
  /** Read session for an asset of `format` (MIME type or extension). */
  create(settings, format) {
    let session = native.sessionNew(format, settings);
    return {
      advance: () => native.sessionAdvance(session),
      fulfill: (id, kind, value) => native.sessionFulfill(session, id, kind,
        kind === "bytes" ? Buffer.from(value.buffer, value.byteOffset, value.byteLength) : value),
      finish: () => native.sessionFinish(session),
      close() { session = undefined }, // Native errors release the handle through isolate GC.
    };
  },
  /**
   * Build session. Rust derives the RSA-PSS signature length from the leaf
   * certificate; `identities` add CAWG identity assertions.
   */
  createBuild(definition, certs, alg, format, identities) {
    const buffers = (list) => list.map((cert) => Buffer.from(cert));
    let session = signing.buildNew(definition, format, alg, buffers(certs),
      identities.map((identity) => ({ ...identity, certs: buffers(identity.certs) })));
    return {
      advance: () => signing.buildAdvance(session),
      fulfill: (id, kind, value) => signing.buildFulfill(session, id, kind,
        kind === "bytes" || kind === "signature" || kind === "timestampResponse" ? Buffer.from(value) : value),
      finish: () => signing.buildFinish(session),
      close() { session = undefined },
    };
  },
};
