/**
 * Worker-side service: executes `read`/`build` commands from a {@link Client}.
 *
 * Operations run one at a time (FIFO) since a Worker owns one session at a
 * time, but signer replies bypass that queue. Errors from an operation are
 * serialized back to the caller; protocol violations throw and are fatal.
 */
import { read, build } from "./drive.mjs";
import { protocol, failure, remoteError } from "./client.mjs";
import { abortError } from "./cancellation.mjs";

export { protocol, failure };

/**
 * Starts serving on `port` and announces readiness.
 * @param {import("./client.mjs").Port} port
 * @param {object} adapter Session factory (`create`, `createBuild`) for this environment.
 */
export function serve(port, adapter) {
  const queue = [];
  let running = false;
  /** Accepted commands, including those waiting in the FIFO queue. */
  const operations = new Map();
  /** Outstanding signer callbacks by command id (at most one per command). */
  const callbacks = new Map();
  function reply(id, ok, value) {
    port.post(ok
      ? { protocol, id, ok: true, value }
      : { protocol, id, ok: false, error: failure(value) });
  }
  function cancel(id) {
    const operation = operations.get(id);
    if (!operation) return;
    operation.controller.abort();
    const callback = callbacks.get(id);
    if (callback) {
      callbacks.delete(id);
      callback.reject(abortError(operation.controller.signal));
    }
    if (operation.state === "queued") {
      const index = queue.indexOf(operation);
      if (index !== -1) queue.splice(index, 1);
      operations.delete(id);
      reply(id, false, abortError(operation.controller.signal));
    }
  }
  async function runNext() {
    if (running) return;
    const operation = queue.shift();
    if (!operation) return;
    running = true;
    operation.state = "running";
    const { message, controller } = operation;
    const started = performance.now();
    try {
      const result = message.method === "read"
        ? await read(adapter, message.asset, message.settings, message.now, controller.signal)
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
          }), controller.signal);
      reply(message.id, true, { ...result, workerMs: performance.now() - started });
    } catch (error) {
      reply(message.id, false, error);
    } finally {
      callbacks.delete(message.id);
      operations.delete(message.id);
      running = false;
      void runNext();
    }
  }
  port.onMessage((message) => {
    if (message.protocol !== protocol) throw new Error("invalid Worker protocol");
    if (message.method === "cancel") {
      cancel(message.id);
      return;
    }
    // Callback replies bypass the operation queue: the active build is waiting
    // for this reply. A reply already in transit when cancellation arrives is stale.
    if (message.method === "signReply") {
      const pending = callbacks.get(message.id);
      if (!pending) {
        if (operations.get(message.id)?.controller.signal.aborted) return;
        throw new Error("unexpected signer reply");
      }
      if (pending.requestId !== message.requestId) throw new Error("unexpected signer reply");
      callbacks.delete(message.id);
      if (message.ok) pending.resolve(message.value);
      else pending.reject(remoteError(message.error));
      return;
    }
    if ((message.method !== "read" && message.method !== "build") ||
        !Number.isSafeInteger(message.id) || message.id < 1 || operations.has(message.id))
      throw new Error("invalid Worker command");
    const operation = { message, controller: new AbortController(), state: "queued" };
    operations.set(message.id, operation);
    queue.push(operation);
    void runNext();
  });
  port.post({ protocol, ready: true });
}
