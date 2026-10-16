import init, { ReadSession } from "../generated/worker_poc_wasm.js";
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
});
