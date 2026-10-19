/** Browser-side client: spawns the module Worker (entry.mjs) and wraps it in a shared Client. */
import { Client } from "../shared/client.mjs";
import { ClientPool } from "../shared/pool.mjs";

/**
 * Starts `workers` module Workers (default 1) behind a {@link ClientPool}.
 * @param {{transport?: "binary"|"json", workers?: number}} [options] `json` is only a control
 *   for the boundary-cost experiment; `binary` is the default.
 */
export function createClient({ transport = "binary", workers = 1 } = {}) {
  return new ClientPool(() => createWorkerClient(transport), { workers });
}

/** Starts one module Worker and returns a {@link Client} bound to it. */
function createWorkerClient(transport) {
  if (transport !== "binary" && transport !== "json") throw new Error("invalid proof transport");
  const url = new URL("./entry.mjs", import.meta.url);
  url.searchParams.set("transport", transport);
  const worker = new Worker(url, { type: "module" });
  return new Client({
    post: (message) => worker.postMessage(message),
    onMessage: (callback) => { worker.onmessage = (event) => callback(event.data) },
    onError(callback) {
      worker.onerror = (event) => { event.preventDefault(); callback(new Error(event.message)) };
      worker.onmessageerror = () => callback(new Error("Worker message decode failed"));
    },
    terminate: () => worker.terminate(),
  });
}
