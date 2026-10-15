import { protocol, type HostMessage, type WorkerMessage } from "../src/worker-protocol.ts";
import type { ReadMetric } from "./performance-types.ts";
import { readAheadBlob, type ReadAheadStats } from "./read-ahead.ts";

const scope = self as DedicatedWorkerGlobalScope;
Date.now = () => Date.parse("2026-09-01T00:00:00Z");
const config = /^c2pa-benchmark-delay-(0|2)-(plain|read-ahead)$/.exec(scope.name);
if (!config) throw new Error("Invalid test-only Worker configuration");
const delay = Number(config[1]);
const readAhead = config[2] === "read-ahead";
if (![0, 2].includes(delay)) throw new Error("Invalid test-only Worker delay");
let operation: { id: number; started: number; reads: ReadMetric[]; readAhead?: ReadAheadStats } | undefined;
scope.addEventListener("message", (event: MessageEvent<HostMessage>) => {
  if (event.data.protocol === protocol && event.data.kind === "command" && event.data.command.method === "read") {
    if (operation) throw new Error("Performance reads must be serial");
    operation = { id: event.data.id, started: performance.now(), reads: [] };
    if (readAhead) {
      const buffered = readAheadBlob(event.data.command.blob);
      event.data.command.blob = buffered.blob;
      operation.readAhead = buffered.stats;
    }
  }
});
const arrayBuffer = Blob.prototype.arrayBuffer;
Blob.prototype.arrayBuffer = async function(): Promise<ArrayBuffer> {
  const active = operation;
  const started = performance.now();
  if (active && delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
  const result = await arrayBuffer.call(this);
  if (result.byteLength !== this.size) throw new Error("Short state-machine Worker host read");
  active?.reads.push({ bytes: result.byteLength, milliseconds: performance.now() - started, transport: "async" });
  return result;
};
const postMessage = scope.postMessage.bind(scope);
scope.postMessage = (message: WorkerMessage) => {
  if (operation && message.protocol === protocol && message.kind === "result" && message.id === operation.id) {
    const completed = operation;
    operation = undefined;
    postMessage({ boundaryWorker: {
      id: completed.id, reads: completed.reads, executionMs: performance.now() - completed.started, delayMs: delay,
      ...(completed.readAhead ? { readAhead: completed.readAhead } : {}),
    } });
  }
  postMessage(message);
};
await import("../src/worker-entry.ts");
