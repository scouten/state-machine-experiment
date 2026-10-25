/**
 * Worker-side service: executes `read`/`build` commands from a {@link Client}.
 *
 * Operations run one at a time (FIFO) since a Worker owns one session at a
 * time, but signer replies bypass that queue. Errors from an operation are
 * serialized back to the caller; protocol violations throw and are fatal.
 */
import { read, build } from "./drive.mjs";
import { protocol, failure, remoteError } from "./client.mjs";
import { openSource } from "./source.mjs";

export { protocol, failure };

/**
 * Starts serving on `port` and announces readiness.
 * @param {import("./client.mjs").Port} port
 * @param {object} adapter Session factory (`create`, `createBuild`) for this environment.
 */
export function serve(port, adapter, open = openSource) {
  let queue = Promise.resolve();
  /** Outstanding signer callbacks by command id (at most one per command). */
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
      let source;
      try {
        if (message.method !== "read" && message.method !== "build")
          throw new Error("invalid Worker command");
        source = await open(message.asset);
        const result = message.method === "read"
          ? await read(adapter, message.asset, message.settings, message.now, source)
          : await build(adapter, message.asset, message.definition, message.certs, (request) =>
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
            }), source);
        const completedSource = source;
        source = undefined;
        await completedSource.close();
        port.post({ protocol, id: message.id, ok: true,
          value: { ...result, workerMs: performance.now() - started } });
      } catch (error) {
        const failedSource = source;
        source = undefined;
        try { await failedSource?.close() }
        catch (cleanup) {
          // The wire retains only name/message, not AggregateError.errors.
          error = new AggregateError([error, cleanup],
            `${String(error)}; source cleanup failed: ${String(cleanup)}`);
        }
        port.post({ protocol, id: message.id, ok: false, error: failure(error) });
      }
    });
  });
  port.post({ protocol, ready: true });
}
