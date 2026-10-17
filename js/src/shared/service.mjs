import { read, build, source, memoryOutput } from "./drive.mjs";
import { protocol, failure, remoteError } from "./client.mjs";

export { protocol, failure };

export function serve(port, adapter, openSource = source, openOutput = () => memoryOutput()) {
  let queue = Promise.resolve();
  const callbacks = new Map();
  port.onMessage((message) => {
    if (message.protocol !== protocol) throw new Error("invalid Worker protocol");
    // Callback replies must bypass the operation queue: its active operation
    // is waiting for this very reply.
    if (message.method === "signReply") {
      const pending = callbacks.get(message.id);
      if (!pending || pending.requestId !== message.requestId)
        throw new Error("unexpected signer reply");
      callbacks.delete(message.id);
      if (message.ok) pending.resolve(message.value);
      else pending.reject(remoteError(message.error));
      return;
    }
    queue = queue.then(async () => {
      const started = performance.now();
      try {
        if (message.method !== "read" && message.method !== "build")
          throw new Error("invalid Worker command");
        const input = await openSource(message.asset);
        let output;
        let result;
        try {
          if (message.method === "build") output = await openOutput(message.destination);
          result = message.method === "read"
            ? await read(adapter, input, message.settings, message.now)
            : await build(adapter, input, message.definition, message.certs, (request) =>
              new Promise((resolve, reject) => {
                if (callbacks.has(message.id)) throw new Error("signer callback already pending");
                callbacks.set(message.id, { requestId: request.id, resolve, reject });
                try {
                  port.post({ protocol, method: "sign", id: message.id,
                    requestId: request.id, alg: request.alg, data: request.data });
                } catch (error) {
                  callbacks.delete(message.id);
                  reject(error);
                }
              }), output);
        } finally {
          try { await output?.close() }
          finally { await input.close() }
        }
        port.post({ protocol, id: message.id, ok: true,
          value: { ...result, workerMs: performance.now() - started } });
      } catch (error) {
        port.post({ protocol, id: message.id, ok: false, error: failure(error) });
      }
    });
  });
  port.post({ protocol, ready: true });
}
