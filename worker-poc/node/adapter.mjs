import { createRequire } from "node:module";

const native = createRequire(import.meta.url)("../../c2pa-node-compat-addon/index.node");
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
};
