/** Node main-thread client: a shared {@link Client} over a `worker_threads` Worker. */
import { Worker } from "node:worker_threads";
import { Client } from "../shared/client.mjs";

/** Starts a Node Worker and returns a Client bound to it. Call `dispose()` when done. */
export function createClient() {
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
