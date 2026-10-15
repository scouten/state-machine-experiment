import { test } from "node:test";
import assert from "node:assert/strict";
import { Context, createC2pa, Reader } from "../src/worker.ts";
import { protocol, type HostMessage, type WorkerMessage } from "../src/worker-protocol.ts";

class FakeWorker {
  static instances: FakeWorker[] = [];
  onmessage?: (event: MessageEvent<unknown>) => void;
  onmessageerror?: () => void;
  onerror?: (event: { message: string; preventDefault(): void }) => void;
  terminated = false;
  messages: HostMessage[] = [];
  constructor() { FakeWorker.instances.push(this) }
  terminate(): void { this.terminated = true }
  postMessage(message: HostMessage): void {
    structuredClone(message);
    this.messages.push(message);
    if (message.kind === "command" && ["init", "read"].includes(message.command.method))
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

test("Worker reads transfer the caller's memoized Context JSON instead of resolving settings again", async (t) => {
  t.after(await setup());
  const loading = createC2pa({ wasmSrc: await module(), workerSrc });
  const worker = FakeWorker.instances[0];
  worker.emit({ protocol, kind: "ready" });
  const client = await loading;
  t.after(() => client.dispose());
  const settings = { verify: { verifyTrust: false, ocspFetch: false } };
  const context = new Context(settings);
  const toJson = t.mock.method(context, "toJson");
  const blob = new Blob([Uint8Array.of(0xff, 0xd8, 0xff, 0xd9)]);
  await Promise.all([Reader.fromBlob(client, "image/jpeg", blob, context),
    Reader.fromBlob(client, "image/jpeg", blob, context)]);
  assert.equal(toJson.mock.callCount(), 2);
  assert.equal(toJson.mock.calls[0].result, toJson.mock.calls[1].result);
  const resolved = await context.toJson();
  settings.verify.verifyTrust = true;
  await Reader.fromBlob(client, "image/jpeg", blob, context);
  const reads = worker.messages.flatMap((message) =>
    message.kind === "command" && message.command.method === "read" ? [message.command] : []);
  assert.equal(reads.length, 3);
  assert.ok(reads.every((read) => read.context?.json === resolved));
  assert.equal(client.liveResources, 0);
});
test("Worker Context resolution failures and disposal while resolving never dispatch a read", async (t) => {
  t.after(await setup());
  const loading = createC2pa({ wasmSrc: await module(), workerSrc });
  const worker = FakeWorker.instances[0];
  worker.emit({ protocol, kind: "ready" });
  const client = await loading;
  t.after(() => client.dispose());
  const context = new Context();
  const toJson = t.mock.method(context, "toJson", () => Promise.reject(new Error("Context failure")));
  const blob = new Blob([]);
  await assert.rejects(Reader.fromBlob(client, "image/jpeg", blob, context), /Context failure/);
  assert.equal(worker.messages.length, 1);
  let release!: (json: string) => void;
  const resolving = new Promise<string>((resolve) => { release = resolve });
  toJson.mock.mockImplementation(() => resolving);
  const pending = Reader.fromBlob(client, "image/jpeg", blob, context);
  client.dispose();
  release("{}");
  await assert.rejects(pending, /disposed/);
  assert.equal(worker.messages.length, 1);
  assert.equal(client.liveResources, 0);
});

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
test("a stale Worker protocol fails initialization instead of silently re-resolving Contexts", async (t) => {
  t.after(await setup());
  const loading = createC2pa({ wasmSrc: await module(), workerSrc });
  const worker = FakeWorker.instances[0];
  const rejected = assert.rejects(loading, /Invalid Worker protocol/);
  worker.onmessage?.(new MessageEvent("message", {
    data: { protocol: "c2pa-state-machine-worker-v1", kind: "ready" },
  }));
  await rejected;
  assert.equal(worker.terminated, true);
  assert.equal(worker.messages.length, 0);
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
