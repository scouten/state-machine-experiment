import { Client } from "../shared/client.mjs";

export function createClient({ transport = "binary" } = {}) {
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
