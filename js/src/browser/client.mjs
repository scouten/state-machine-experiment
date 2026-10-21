/** Browser-side client: spawns the module Worker (entry.mjs) and wraps it in a shared Client. */
import { Client } from "../shared/client.mjs";

/**
 * @param {{transport?: "leased"|"binary"|"json"}} [options] `binary` and `json`
 *   are controls for the boundary-cost experiment; `leased` is the default.
 */
export function createClient({ transport = "leased" } = {}) {
  if (!["leased", "binary", "json"].includes(transport)) throw new Error("invalid proof transport");
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
