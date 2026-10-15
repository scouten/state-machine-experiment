import { Context, validateAssetSize, type Settings } from "@contentauth/c2pa-utilities";
import { MAX_SIZE_IN_BYTES, type ManifestAndAssetBytes, type ManifestProjection, type Signer } from "./index.ts";
import { isProjection } from "./projection.ts";
import { remoteManifestHost, type RemoteManifestOptions } from "./remote.ts";
import { ocspHost, type OcspOptions } from "./ocsp.ts";
import { failure, protocol, restore, type Command, type HostMessage, type WorkerMessage } from "./worker-protocol.ts";
import { contextJson, factoryContext, readerDefaults, rejectBuilderDefaults } from "./settings.ts";

export { Context, AssetTooLargeError } from "@contentauth/c2pa-utilities";
export { MAX_SIZE_IN_BYTES };
export type { ManifestAndAssetBytes, ManifestProjection, Signer, RemoteManifestOptions, OcspOptions };
export interface Config { wasmSrc: string | WebAssembly.Module; workerSrc: URL; settings?: Settings }
interface Pending {
  resolve(value: unknown): void;
  reject(error: Error): void;
  signer?: Signer;
}
function resourceId(value: unknown): number {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value <= 0)
    throw new Error("Invalid Worker resource handle");
  return value;
}

export async function createC2pa(config: Config): Promise<Runtime> {
  if (Object.keys(config).some((key) => !["wasmSrc", "workerSrc", "settings"].includes(key)))
    throw new Error("Unsupported Worker loader configuration");
  if (!(config.workerSrc instanceof URL)) throw new Error("Worker loader requires an explicit workerSrc URL");
  const defaults = readerDefaults(config.settings);
  const source = typeof config.wasmSrc === "string" ? new URL(config.wasmSrc, location.href).href : config.wasmSrc;
  const runtime = new Runtime(new Worker(config.workerSrc, { type: "module", name: "c2pa-state-machine" }), defaults);
  const deadline = setTimeout(() => runtime.fail(new Error("Worker initialization deadline exceeded")), 30_000);
  try {
    await runtime.ready;
    await runtime.call({ method: "init", source });
    return runtime;
  } catch (cause) { runtime.dispose(); throw cause }
  finally { clearTimeout(deadline) }
}

export class Runtime {
  #defaults: Settings;
  #worker: Worker;
  #closed: Error | undefined;
  #next = 1;
  #pending = new Map<number, Pending>();
  #resources = new Set<Resource>();
  #resolveReady!: () => void;
  #rejectReady!: (error: Error) => void;
  #started = false;
  readonly ready = new Promise<void>((resolve, reject) => { this.#resolveReady = resolve; this.#rejectReady = reject });
  constructor(worker: Worker, defaults: Settings = {}) {
    this.#defaults = readerDefaults(defaults);
    this.#worker = worker;
    worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
      try {
        const message = event.data;
        if (message.protocol !== protocol) { this.fail(new Error("Invalid Worker protocol")); return }
        if (message.kind === "ready") {
          if (this.#started) throw new Error("Duplicate Worker readiness message");
          this.#started = true;
          this.#resolveReady();
        } else if (message.kind === "result") {
          const pending = this.#pending.get(message.id);
          if (!pending) { this.fail(new Error("Unexpected Worker result")); return }
          this.#pending.delete(message.id);
          if (message.outcome.ok) pending.resolve(message.outcome.value);
          else pending.reject(restore(message.outcome.error));
        } else if (message.kind === "callback") {
          void this.#callback(message);
        } else this.fail(new Error("Invalid Worker message"));
      } catch (cause) { this.fail(restore(failure(cause))) }
    };
    worker.onerror = (event) => { event.preventDefault(); this.fail(new Error(event.message || "Worker failed to load or execute")) };
    worker.onmessageerror = () => this.fail(new Error("Worker message could not be decoded"));
  }
  async #callback(message: Extract<WorkerMessage, { kind: "callback" }>): Promise<void> {
    const signer = this.#pending.get(message.operation)?.signer;
    let outcome: Extract<HostMessage, { kind: "callbackResult" }>["outcome"];
    try {
      if (!signer) throw new Error("Invalid Worker signing callback operation");
      if (!(message.bytes instanceof Uint8Array)) throw new Error("Invalid Worker callback bytes");
      let value: Uint8Array;
      if (message.method === "sign") value = await signer.sign(message.bytes);
      else if (message.method === "timestamp") {
        if (!signer.sendTimestampRequest || typeof message.url !== "string")
          throw new Error("Timestamp host is not configured");
        value = await signer.sendTimestampRequest(message.url, message.bytes);
      } else throw new Error("Invalid Worker callback method");
      if (!(value instanceof Uint8Array)) throw new Error("Worker callback must return Uint8Array");
      outcome = { ok: true, value };
    } catch (cause) { outcome = { ok: false, error: failure(cause) } }
    if (!this.#closed) {
      try { this.#worker.postMessage({ protocol, kind: "callbackResult", id: message.id, outcome } satisfies HostMessage) }
      catch (cause) { this.fail(restore(failure(cause))) }
    }
  }
  get liveResources(): number { return this.#resources.size }
  get disposed(): boolean { return this.#closed !== undefined }
  assertLive(): void { if (this.#closed) throw this.#closed }
  retain(resource: Resource): void { this.assertLive(); this.#resources.add(resource) }
  release(resource: Resource): void { this.#resources.delete(resource) }
  fail(error: Error): void {
    if (this.#closed) return;
    this.#closed = error;
    this.#rejectReady(error);
    this.#worker.terminate();
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#resources.clear();
  }
  dispose(): void { this.fail(new Error("Runtime has been disposed")) }
  async call(command: Command, signer?: Signer, signals?: { remote?: AbortSignal; ocsp?: AbortSignal }): Promise<unknown> {
    this.assertLive();
    const id = this.#next++;
    const cleanups: (() => void)[] = [];
    try {
      return await new Promise<unknown>((resolve, reject) => {
        this.#pending.set(id, { resolve, reject, signer });
        try {
          this.#worker.postMessage({ protocol, kind: "command", id, command } satisfies HostMessage);
          for (const channel of ["remote", "ocsp"] as const) {
            const signal = signals?.[channel];
            if (!signal) continue;
            const abort = () => {
              if (!this.#closed) {
                try { this.#worker.postMessage({ protocol, kind: "abort", id, channel, error: failure(signal.reason) } satisfies HostMessage) }
                catch (cause) { this.fail(restore(failure(cause))) }
              }
            };
            signal.addEventListener("abort", abort, { once: true });
            cleanups.push(() => signal.removeEventListener("abort", abort));
            if (signal.aborted) abort();
          }
        } catch (cause) { this.#pending.delete(id); reject(restore(failure(cause))) }
      });
    } finally { for (const cleanup of cleanups) cleanup() }
  }
  reader = {
    fromBlob: async (format: string | undefined, blob: Blob, settings?: Settings, detached?: Uint8Array,
      remote?: RemoteManifestOptions, ocsp?: OcspOptions) =>
      await Reader.fromBlob(this, format, blob, factoryContext(this.#defaults, settings), detached, remote, ocsp),
  };
  builder = {
    fromDefinition: async (definition: Record<string, unknown>) => {
      rejectBuilderDefaults(this.#defaults);
      return await Builder.fromDefinition(this, definition);
    },
  };
}

abstract class Resource {
  #freed = false;
  #runtime: Runtime;
  #handle: number;
  protected constructor(runtime: Runtime, handle: number) { this.#runtime = runtime; this.#handle = handle }
  protected get runtime(): Runtime { return this.#runtime }
  protected get handle(): number { return this.#handle }
  protected live(): void {
    this.runtime.assertLive();
    if (this.#freed) throw new Error(`${this.constructor.name} has been freed`);
  }
  async free(): Promise<void> {
    if (this.#freed) return;
    this.#freed = true;
    this.runtime.release(this);
    if (!this.runtime.disposed) await this.runtime.call({ method: "free", handle: this.handle });
  }
}
export class Reader extends Resource {
  private constructor(runtime: Runtime, handle: number) { super(runtime, handle); runtime.retain(this) }
  static async fromBlob(runtime: Runtime, format: string | undefined, blob: Blob, context?: Context,
    detached?: Uint8Array, remote?: RemoteManifestOptions, ocsp?: OcspOptions): Promise<Reader | null> {
    runtime.assertLive();
    validateAssetSize(blob.size, MAX_SIZE_IN_BYTES);
    // Validate policy before crossing the boundary; the Worker creates the actual fetch hosts.
    if (remote) remoteManifestHost(remote);
    if (ocsp) ocspHost(ocsp);
    const network = (options: RemoteManifestOptions | OcspOptions | undefined) => options ? {
      allowedOrigins: [...options.allowedOrigins], maxBytes: options.maxBytes, timeoutMs: options.timeoutMs,
    } : undefined;
    const json = await contextJson(context, ocsp !== undefined);
    const value = await runtime.call({ method: "read", format, blob,
      context: json === undefined ? undefined : { settings: context?.settings, json },
      detached, remote: network(remote), ocsp: network(ocsp) }, undefined,
      { remote: remote?.signal, ocsp: ocsp?.signal });
    return value === null ? null : new Reader(runtime, resourceId(value));
  }
  async activeLabel(): Promise<string | null> {
    this.live();
    const value = await this.runtime.call({ method: "readerMethod", handle: this.handle, name: "activeLabel" });
    if (value !== null && typeof value !== "string") throw new Error("Invalid Worker active label");
    return value;
  }
  async activeManifest(): Promise<unknown> {
    this.live();
    return await this.runtime.call({ method: "readerMethod", handle: this.handle, name: "activeManifest" });
  }
  async manifestStore(): Promise<ManifestProjection> { return await this.#projection("manifestStore") }
  async resourceToBytes(uri: string): Promise<Uint8Array> {
    this.live();
    if (typeof uri !== "string") throw new TypeError("Resource identifier must be a string");
    const value = await this.runtime.call({ method: "resourceToBytes", handle: this.handle, uri });
    if (!(value instanceof Uint8Array)) throw new Error("Invalid Worker resource bytes");
    return value;
  }
  async json(): Promise<ManifestProjection> { return await this.#projection("json") }
  async #projection(name: "manifestStore" | "json"): Promise<ManifestProjection> {
    this.live();
    const value = await this.runtime.call({ method: "readerMethod", handle: this.handle, name });
    if (!isProjection(value)) throw new Error("Invalid Worker manifest projection");
    return value;
  }
}
export class Builder extends Resource {
  #busy = false;
  private constructor(runtime: Runtime, handle: number) { super(runtime, handle); runtime.retain(this) }
  static async fromDefinition(runtime: Runtime, definition: Record<string, unknown>): Promise<Builder> {
    runtime.assertLive();
    return new Builder(runtime, resourceId(await runtime.call({ method: "builder", definition })));
  }
  async sign(signer: Signer, format: string, blob: Blob): Promise<ManifestAndAssetBytes> {
    return await this.#sign(signer, blob, format);
  }
  async signDetached(signer: Signer, blob: Blob): Promise<ManifestAndAssetBytes> {
    return await this.#sign(signer, blob);
  }
  async #sign(signer: Signer, blob: Blob, format?: string): Promise<ManifestAndAssetBytes> {
    this.live();
    if (this.#busy) throw new Error("Builder already has an in-flight operation");
    validateAssetSize(blob.size, MAX_SIZE_IN_BYTES);
    this.#busy = true;
    try {
      const value = await this.runtime.call({ method: "sign", handle: this.handle, format, blob,
        signer: { alg: signer.alg, certs: signer.certs, timeAuthorityUrl: signer.timeAuthorityUrl,
          timestamp: signer.sendTimestampRequest !== undefined } }, signer);
      this.live();
      if (value === null || typeof value !== "object" || !("asset" in value) || !("manifest" in value) ||
          !(value.asset instanceof Uint8Array) || !(value.manifest instanceof Uint8Array))
        throw new Error("Invalid Worker signing result");
      return { asset: value.asset, manifest: value.manifest };
    } finally { this.#busy = false }
  }
}
