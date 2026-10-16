import { Client } from "../shared/client.mjs";

export function createClient() {
  const worker = new Worker(new URL("./entry.mjs", import.meta.url), { type: "module" });
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
