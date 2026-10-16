import { Worker } from "node:worker_threads";
import { Client } from "../shared/client.mjs";

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
