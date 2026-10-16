import { createRequire } from "node:module";

const native = createRequire(import.meta.url)("../../../c2pa-node-compat-addon/index.node");
const signing = createRequire(import.meta.url)("../../../c2pa-node-sign-addon/index.node");
export const adapter = {
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
  createBuild(definition, certs) {
    let session = signing.buildNew(definition, "image/jpeg", "es256", certs.map((cert) => Buffer.from(cert)));
    return {
      advance: () => signing.buildAdvance(session),
      fulfill: (id, kind, value) => signing.buildFulfill(session, id, kind,
        kind === "bytes" || kind === "signature" ? Buffer.from(value) : value),
      finish: () => signing.buildFinish(session),
      close() { session = undefined },
    };
  },
};
