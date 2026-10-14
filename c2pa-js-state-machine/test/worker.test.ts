import { test } from "node:test";
import assert from "node:assert/strict";
import { createC2pa } from "../src/worker.ts";
import { protocol, type HostMessage, type WorkerMessage } from "../src/worker-protocol.ts";

class FakeWorker {
  static instances: FakeWorker[] = [];
  onmessage?: (event: MessageEvent<WorkerMessage>) => void;
  onmessageerror?: () => void;
  onerror?: (event: { message: string; preventDefault(): void }) => void;
  terminated = false;
  constructor() { FakeWorker.instances.push(this) }
  terminate(): void { this.terminated = true }
  postMessage(message: HostMessage): void {
    structuredClone(message);
    if (message.kind === "command" && message.command.method === "init")
      queueMicrotask(() => this.emit({ protocol, kind: "result", id: message.id, outcome: { ok: true, value: null } }));
  }
  emit(data: WorkerMessage): void { this.onmessage?.(new MessageEvent("message", { data })) }
}
async function setup(): Promise<() => void> {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "Worker");
  Object.defineProperty(globalThis, "Worker", { value: FakeWorker, configurable: true });
  FakeWorker.instances = [];
  return () => {
    if (descriptor) Object.defineProperty(globalThis, "Worker", descriptor);
    else Reflect.deleteProperty(globalThis, "Worker");
  };
}
const module = () => WebAssembly.compile(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
const workerSrc = new URL("https://example.invalid/worker.js");

test("Worker readiness deadline terminates the Worker and rejects instead of hanging", async (t) => {
  const cleanup = await setup();
  t.after(cleanup);
  const wasmSrc = await module();
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const loading = createC2pa({ wasmSrc, workerSrc });
  const rejected = assert.rejects(loading, /initialization deadline/);
  t.mock.timers.tick(30_000);
  await rejected;
  assert.equal(FakeWorker.instances[0].terminated, true);
});
test("Worker startup and message errors reject pending work and terminate ownership", async (t) => {
  const cleanup = await setup();
  t.after(cleanup);
  const wasmSrc = await module();
  const loading = createC2pa({ wasmSrc, workerSrc });
  const rejected = assert.rejects(loading, /startup failed/);
  FakeWorker.instances[0].onerror?.({ message: "startup failed", preventDefault() {} });
  await rejected;
  assert.equal(FakeWorker.instances[0].terminated, true);
  const retry = createC2pa({ wasmSrc, workerSrc });
  const worker = FakeWorker.instances[1];
  worker.emit({ protocol, kind: "ready" });
  const client = await retry;
  const pending = client.call({ method: "builder", definition: {} });
  const failed = assert.rejects(pending, /could not be decoded/);
  worker.onmessageerror?.();
  await failed;
  assert.equal(worker.terminated, true);
  assert.equal(client.liveResources, 0);
});
test("Worker clone errors reject only the operation and disposal rejects outstanding work", async (t) => {
  const cleanup = await setup();
  t.after(cleanup);
  const loading = createC2pa({ wasmSrc: await module(), workerSrc });
  const worker = FakeWorker.instances[0];
  worker.emit({ protocol, kind: "ready" });
  const client = await loading;
  await assert.rejects(client.call({ method: "builder", definition: { invalid() {} } }), /clone/i);
  assert.equal(worker.terminated, false);
  const pending = client.call({ method: "builder", definition: {} });
  const failed = assert.rejects(pending, /disposed/);
  client.dispose();
  await failed;
  assert.equal(worker.terminated, true);
});
