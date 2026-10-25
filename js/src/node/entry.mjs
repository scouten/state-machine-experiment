/** Node Worker entry point: serves the shared protocol with the Neon adapter. */
import { parentPort } from "node:worker_threads";
import { adapter } from "./adapter.mjs";
import { serve } from "../shared/service.mjs";
import { openNodeSource } from "./source.mjs";

serve({
  post: (message) => parentPort.postMessage(message),
  onMessage: (callback) => parentPort.on("message", callback),
}, adapter, openNodeSource);
