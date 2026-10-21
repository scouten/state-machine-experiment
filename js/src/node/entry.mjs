/** Node Worker entry point: serves the shared protocol with the Neon adapter. */
import { parentPort } from "node:worker_threads";
import { adapter } from "./adapter.mjs";
import { serve } from "../shared/service.mjs";

serve({
  post: (message, transfer) => parentPort.postMessage(message, transfer),
  onMessage: (callback) => parentPort.on("message", callback),
}, adapter);
