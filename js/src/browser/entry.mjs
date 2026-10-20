/**
 * Browser Worker entry point: wraps the Wasm `ReadSession`/`BuildSession`
 * in the adapter shape `serve()` expects (see shared/service.mjs).
 * Loaded as a module Worker by browser/client.mjs.
 */
import init, * as wasm from "../../generated/contentauth_c2pa_wasm.js";
import { createWasmAdapter } from "./adapter.mjs";
import { serve } from "../shared/service.mjs";

await init();
// The JSON control is retained only for the boundary experiment.
const binary = new URL(self.location.href).searchParams.get("transport") !== "json";
serve({
  post: (message) => self.postMessage(message),
  onMessage: (callback) => { self.onmessage = (event) => callback(event.data) },
}, createWasmAdapter(wasm, { binary }));
