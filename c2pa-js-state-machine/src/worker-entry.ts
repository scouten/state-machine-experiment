import { Builder, Context, createC2pa, Reader, type Runtime, type Signer } from "./index.ts";
import { failure, protocol, restore, type Command, type HostMessage, type Outcome, type WorkerMessage } from "./worker-protocol.ts";

const scope = self as DedicatedWorkerGlobalScope;
let runtime: Runtime | undefined;
let nextHandle = 1;
let nextCallback = 1;
const handles = new Map<number, Reader | Builder>();
const callbacks = new Map<number, { resolve(value: Uint8Array): void; reject(error: Error): void }>();
const reads = new Map<number, { remote: AbortController; ocsp: AbortController }>();
const send = (message: WorkerMessage) => scope.postMessage(message);

function live(): Runtime {
  if (!runtime) throw new Error("Worker runtime has not been initialized");
  runtime.assertLive();
  return runtime;
}
function handle(id: number): Reader | Builder {
  live();
  const resource = handles.get(id);
  if (!resource) throw new Error("Invalid Worker resource handle");
  return resource;
}
function retain(resource: Reader | Builder): number {
  const id = nextHandle++;
  handles.set(id, resource);
  return id;
}
function callback(operation: number, method: "sign" | "timestamp", bytes: Uint8Array, url?: string): Promise<Uint8Array> {
  const id = nextCallback++;
  return new Promise((resolve, reject) => {
    callbacks.set(id, { resolve, reject });
    try { send({ protocol, kind: "callback", id, operation, method, bytes, url }) }
    catch (cause) { callbacks.delete(id); reject(restore(failure(cause))) }
  });
}
async function execute(id: number, command: Command): Promise<unknown> {
  switch (command.method) {
    case "init":
      if (runtime) throw new Error("Worker runtime is already initialized");
      runtime = await createC2pa({ wasmSrc: command.source });
      return null;
    case "read": {
      const client = live();
      const controllers = { remote: new AbortController(), ocsp: new AbortController() };
      reads.set(id, controllers);
      try {
        const reader = await Reader.fromBlob(client, command.format, command.blob,
          command.settings ? new Context(command.settings) : undefined, command.detached,
          command.remote ? { ...command.remote, signal: controllers.remote.signal } : undefined,
          command.ocsp ? { ...command.ocsp, signal: controllers.ocsp.signal } : undefined);
        return reader ? retain(reader) : null;
      } finally { reads.delete(id) }
    }
    case "builder": return retain(await Builder.fromDefinition(live(), command.definition));
    case "readerMethod": {
      const resource = handle(command.handle);
      if (!(resource instanceof Reader)) throw new Error("Worker handle is not a Reader");
      return await resource[command.name]();
    }
    case "sign": {
      const resource = handle(command.handle);
      if (!(resource instanceof Builder)) throw new Error("Worker handle is not a Builder");
      const signer: Signer = {
        alg: command.signer.alg, certs: command.signer.certs,
        timeAuthorityUrl: command.signer.timeAuthorityUrl,
        sign: (bytes) => callback(id, "sign", bytes),
        ...(command.signer.timestamp ? {
          sendTimestampRequest: (url: string, bytes: Uint8Array) => callback(id, "timestamp", bytes, url),
        } : {}),
      };
      return command.format === undefined
        ? await resource.signDetached(signer, command.blob)
        : await resource.sign(signer, command.format, command.blob);
    }
    case "free": {
      const resource = handle(command.handle);
      handles.delete(command.handle);
      await resource.free();
      return null;
    }
  }
  throw new Error("Unknown Worker command");
}
scope.onmessage = (event: MessageEvent<HostMessage>) => {
  const message = event.data;
  if (message.protocol !== protocol) throw new Error("Invalid Worker protocol");
  if (message.kind === "callbackResult") {
    const pending = callbacks.get(message.id);
    if (!pending) throw new Error("Invalid Worker callback handle");
    callbacks.delete(message.id);
    if (!message.outcome.ok) pending.reject(restore(message.outcome.error));
    else if (message.outcome.value instanceof Uint8Array) pending.resolve(message.outcome.value);
    else pending.reject(new Error("Worker callback must return Uint8Array"));
  } else if (message.kind === "abort") {
    reads.get(message.id)?.[message.channel].abort(restore(message.error));
  } else if (message.kind === "command") {
    void (async () => {
      let outcome: Outcome;
      try { outcome = { ok: true, value: await execute(message.id, message.command) } }
      catch (cause) { outcome = { ok: false, error: failure(cause) } }
      try { send({ protocol, kind: "result", id: message.id, outcome }) }
      catch (cause) {
        send({ protocol, kind: "result", id: message.id, outcome: { ok: false, error: failure(cause) } });
      }
    })();
  } else throw new Error("Invalid Worker message");
};
scope.onmessageerror = () => { throw new Error("Worker message could not be decoded") };
send({ protocol, kind: "ready" });
