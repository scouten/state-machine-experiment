import { createC2pa, Reader } from "../src/worker.ts";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import workerSrc from "c2pa-js-state-machine/worker-entry?worker&url";

const violations: string[] = [];
document.addEventListener("securitypolicyviolation", (event) => { violations.push(event.effectiveDirective) });
let client;
try {
  client = await createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href) });
  const reader = await Reader.fromBlob(client, "image/jpeg", new Blob([Uint8Array.of(0xff, 0xd8, 0xff, 0xd9)]));
  if (reader !== null) throw new Error("Expected unsigned CSP fixture");
  parent.postMessage({ kind: "c2pa-worker-csp", ok: true, violations }, location.origin);
} catch (cause) {
  // CSP events may be queued behind the Worker error.
  await new Promise((resolve) => setTimeout(resolve, 0));
  parent.postMessage({ kind: "c2pa-worker-csp", ok: false,
    error: cause instanceof Error ? cause.message : String(cause), violations }, location.origin);
} finally { client?.dispose() }
