import { read } from "./drive.mjs";
import { protocol } from "./client.mjs";

export { protocol };
export function failure(error) {
  return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
}

export function serve(port, adapter) {
  let queue = Promise.resolve();
  port.onMessage((message) => {
    queue = queue.then(async () => {
      const started = performance.now();
      try {
        if (message.protocol !== protocol || message.method !== "read")
          throw new Error("invalid Worker command");
        const result = await read(adapter, message.asset, message.settings, message.now);
        port.post({ protocol, id: message.id, ok: true,
          value: { ...result, workerMs: performance.now() - started } });
      } catch (error) {
        port.post({ protocol, id: message.id, ok: false, error: failure(error) });
      }
    });
  });
  port.post({ protocol, ready: true });
}
