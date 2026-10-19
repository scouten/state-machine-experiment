/** Node main-thread client: a shared {@link Client} over a `worker_threads` Worker. */
import { Worker } from "node:worker_threads";
import { Client } from "../shared/client.mjs";
import { ClientPool } from "../shared/pool.mjs";

/**
 * Starts `workers` Node Workers (default 1) behind a {@link ClientPool}.
 * Call `dispose()` when done.
 * @param {{workers?: number}} [options]
 */
export function createClient({ workers = 1 } = {}) {
  return new ClientPool(createWorkerClient, { workers });
}

/** Starts one Node Worker and returns a {@link Client} bound to it. */
function createWorkerClient() {
  const worker = new Worker(new URL("./entry.mjs", import.meta.url));
  let terminating;
  return new Client({
    post: (message) => worker.postMessage(message),
    onMessage: (callback) => worker.on("message", callback),
    onError(callback) {
      worker.on("error", callback);
      worker.on("exit", (code) => callback(new Error(`Worker exited (${code})`)));
      worker.on("messageerror", callback);
    },
    terminate: () => terminating ??= worker.terminate(),
  });
}
