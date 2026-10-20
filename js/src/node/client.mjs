/** Node main-thread client: a shared {@link Client} over a `worker_threads` Worker. */
import { Worker } from "node:worker_threads";
import { resolve, dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { removeTemporary } from "./output.mjs";
import { Client, snapshotAsset } from "../shared/client.mjs";

export function snapshotNodeAsset(asset) {
  if (asset && typeof asset === "object" && "path" in asset) {
    if (typeof asset.path !== "string" || asset.path.length === 0)
      throw new TypeError("asset.path must be a nonempty string");
    return { path: resolve(asset.path) };
  }
  return snapshotAsset(asset);
}

/** Starts a Node Worker and returns a Client bound to it. Call `dispose()` when done. */
export function createClient() {
  const worker = new Worker(new URL("./entry.mjs", import.meta.url));
  let terminating;
  const temporary = new Map();
  return new Client({
    post(message) {
      if (message.destination) {
        message.destination.temporary = join(dirname(message.destination.path), `.c2pa-${randomUUID()}.tmp`);
        temporary.set(message.id, message.destination.temporary);
      }
      worker.postMessage(message);
    },
    onMessage: (callback) => worker.on("message", (message) => {
      // Failed replies may include failed unlink attempts; retain them for disposal.
      if (message.method !== "sign" && message.ok) temporary.delete(message.id);
      callback(message);
    }),
    onError(callback) {
      worker.on("error", callback);
      worker.on("exit", (code) => callback(new Error(`Worker exited (${code})`)));
      worker.on("messageerror", callback);
    },
    terminate: () => terminating ??= (async () => {
      await worker.terminate();
      await Promise.all([...temporary.values()].map(removeTemporary));
    })(),
  }, snapshotNodeAsset, (destination) => {
    if (!destination || typeof destination.path !== "string" || !destination.path.length)
      throw new TypeError("destination.path must be a nonempty string");
    return { path: resolve(destination.path) };
  });
}
