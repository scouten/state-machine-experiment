import init, { BrowserBuilder, BrowserReader } from "../.cache/generated/state_machine.js";
import { Context, validateAssetSize, type Settings } from "@contentauth/c2pa-utilities";
import { remoteManifestHost, type RemoteManifestOptions } from "./remote.ts";
export type { RemoteManifestOptions } from "./remote.ts";
import { ocspHost, type OcspOptions } from "./ocsp.ts";
import { isProjection } from "./projection.ts";
import { contextJson, factoryContext, readerDefaults, rejectBuilderDefaults, type ReaderContext } from "./settings.ts";
export type { OcspOptions } from "./ocsp.ts";

export { Context, AssetTooLargeError } from "@contentauth/c2pa-utilities";
export type { Runtime };
export const MAX_SIZE_IN_BYTES = 10 ** 9;
export interface Config {
  wasmSrc: string | WebAssembly.Module;
  workerSrc?: URL;
  settings?: Settings;
}
export interface ManifestProjection {
  active_manifest?: string;
  manifests: Record<string, unknown>;
  validation_state: "Trusted" | "Valid" | "Invalid";
  validation_status?: { code: string; url?: string; explanation?: string }[];
  validation_results: {
    activeManifest: {
      success: { code: string; url?: string; explanation?: string }[];
      informational: { code: string; url?: string; explanation?: string }[];
      failure: { code: string; url?: string; explanation?: string }[];
    };
    specVersion: string;
  };
}
export interface Signer {
  alg: "es256";
  certs: Uint8Array[];
  sign(data: Uint8Array): Promise<Uint8Array>;
  timeAuthorityUrl?: string;
  sendTimestampRequest?(url: string, request: Uint8Array): Promise<Uint8Array>;
}
export interface ManifestAndAssetBytes { asset: Uint8Array; manifest: Uint8Array }

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function error(cause: unknown): Error {
  return cause instanceof Error ? cause : new Error(String(cause), { cause });
}
function projection(value: unknown): ManifestProjection {
  if (!isProjection(value))
    throw new Error("Invalid state-machine manifest projection");
  return value;
}
let source: Config["wasmSrc"] | undefined;
let loading: Promise<void> | undefined;
export async function createC2pa(config: Config): Promise<Runtime> {
  if (Object.keys(config).some((key) => !["wasmSrc", "workerSrc", "settings"].includes(key)))
    throw new Error("Unsupported M1 loader configuration");
  if (config.workerSrc !== undefined)
    throw new Error("The loader is inline-only; Worker configuration is not supported");
  const defaults = readerDefaults(config.settings);
  if (source !== undefined && source !== config.wasmSrc)
    throw new Error("The inline Wasm module is already initialized with a different resource");
  if (!loading) {
    source = config.wasmSrc;
    loading = init({ module_or_path: config.wasmSrc }).then(() => undefined).catch((cause: unknown) => {
      source = undefined;
      loading = undefined;
      throw error(cause);
    });
  }
  await loading;
  return new Runtime(defaults);
}

interface Resource { requestFree(): void }
class Runtime {
  #defaults: Settings;
  constructor(defaults: Settings) { this.#defaults = defaults }
  #disposed = false;
  #resources = new Set<Resource>();
  get liveResources(): number { return this.#resources.size }
  assertLive(): void { if (this.#disposed) throw new Error("Runtime has been disposed") }
  retain(resource: Resource): void { this.assertLive(); this.#resources.add(resource) }
  release(resource: Resource): void { this.#resources.delete(resource) }
  dispose(): void {
    this.#disposed = true;
    for (const resource of this.#resources) resource.requestFree();
  }
  reader = {
    fromBlob: async (format: string, blob: Blob, settings?: Settings, detachedManifest?: Uint8Array,
      remoteManifest?: RemoteManifestOptions, ocsp?: OcspOptions) =>
      await Reader.fromBlob(this, format, blob, factoryContext(this.#defaults, settings),
        detachedManifest, remoteManifest, ocsp),
  };
  builder = {
    fromDefinition: async (definition: Record<string, unknown>) => {
      rejectBuilderDefaults(this.#defaults);
      return await Builder.fromDefinition(this, definition);
    },
  };
}

export class Reader implements Resource {
  #runtime: Runtime;
  #ffi: BrowserReader | undefined;
  private constructor(runtime: Runtime, ffi: BrowserReader) {
    this.#runtime = runtime;
    this.#ffi = ffi;
    runtime.retain(this);
  }
  static async fromBlob(
    runtime: Runtime,
    format: string | undefined,
    blob: Blob,
    context?: ReaderContext,
    detachedManifest?: Uint8Array,
    remoteManifest?: RemoteManifestOptions,
    ocsp?: OcspOptions,
  ): Promise<Reader | null> {
    runtime.assertLive();
    validateAssetSize(blob.size, MAX_SIZE_IN_BYTES);
    if (!format) {
      const bytes = new Uint8Array(await blob.slice(0, 4).arrayBuffer());
      if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) format = "image/jpeg";
      else if ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[3] === 0 &&
                (bytes[2] === 42 || bytes[2] === 43)) ||
               (bytes[0] === 0x4d && bytes[1] === 0x4d && bytes[2] === 0 &&
                (bytes[3] === 42 || bytes[3] === 43))) format = "image/tiff";
      else throw new Error("Unsupported state-machine asset format");
    }
    const remoteHost = remoteManifest ? remoteManifestHost(remoteManifest) : undefined;
    const ocspTransport = ocsp ? ocspHost(ocsp) : undefined;
    const baseJson = await contextJson(context, ocspTransport !== undefined);
    let json = baseJson;
    if (remoteHost || ocspTransport) {
      const parsed: unknown = JSON.parse(baseJson ?? "{}");
      if (!object(parsed) || (parsed.verify !== undefined && !object(parsed.verify)))
        throw new Error("Invalid serialized Context");
      json = JSON.stringify({
        ...parsed, verify: { ...parsed.verify,
          ...(remoteHost ? { remote_manifest_fetch: true } : {}),
          ...(ocspTransport ? { ocsp_fetch: true } : {}),
        },
      });
    }
    runtime.assertLive();
    let ffi: BrowserReader;
    try { ffi = await BrowserReader.fromBlob(format, blob, json, detachedManifest, remoteHost, ocspTransport) }
    catch (cause) {
      runtime.assertLive();
      if (cause === "C2pa(JumbfNotFound)") return null;
      throw error(cause);
    }
    try { runtime.assertLive() }
    catch (cause) { ffi.free(); throw cause }
    return new Reader(runtime, ffi);
  }
  #handle(): BrowserReader {
    this.#runtime.assertLive();
    if (!this.#ffi) throw new Error("Reader has been freed");
    return this.#ffi;
  }
  async activeLabel(): Promise<string | null> { return this.#handle().activeLabel() ?? null }
  async activeManifest(): Promise<unknown> { return this.#handle().activeManifest() }
  async resourceToBytes(uri: string): Promise<Uint8Array> {
    const handle = this.#handle();
    if (typeof uri !== "string") throw new TypeError("Resource identifier must be a string");
    try { return handle.resourceToBytes(uri) }
    catch (cause) { throw error(cause) }
  }
  async manifestStore(): Promise<ManifestProjection> { return projection(this.#handle().manifestStore()) }
  async json(): Promise<ManifestProjection> {
    try { return projection(JSON.parse(this.#handle().json()) as unknown) }
    catch (cause) { throw error(cause) }
  }
  requestFree(): void {
    this.#ffi?.free();
    this.#ffi = undefined;
    this.#runtime.release(this);
  }
  async free(): Promise<void> { this.requestFree() }
}

export class Builder implements Resource {
  #runtime: Runtime;
  #ffi: BrowserBuilder | undefined;
  #busy = false;
  #closed = false;
  private constructor(runtime: Runtime, ffi: BrowserBuilder) {
    this.#runtime = runtime;
    this.#ffi = ffi;
    runtime.retain(this);
  }
  static async fromDefinition(runtime: Runtime, definition: Record<string, unknown>): Promise<Builder> {
    runtime.assertLive();
    const complete = { ...definition,
      instance_id: definition.instance_id === undefined ? `xmp:iid:${crypto.randomUUID()}` : definition.instance_id,
      label: definition.label === undefined ? `urn:uuid:${crypto.randomUUID()}` : definition.label,
    };
    let ffi: BrowserBuilder;
    try { ffi = BrowserBuilder.fromJson(JSON.stringify(complete)) }
    catch (cause) { throw error(cause) }
    return new Builder(runtime, ffi);
  }
  async sign(signer: Signer, format: string, blob: Blob): Promise<ManifestAndAssetBytes> {
    this.#runtime.assertLive();
    if (this.#closed || !this.#ffi) throw new Error("Builder has been freed");
    if (this.#busy) throw new Error("Builder already has an in-flight operation");
    validateAssetSize(blob.size, MAX_SIZE_IN_BYTES);
    this.#busy = true;
    try {
      const result: unknown = await this.#ffi.sign(signer, format, blob);
      this.#runtime.assertLive();
      if (this.#closed) throw new Error("Builder has been freed");
      if (!object(result) || !(result.asset instanceof Uint8Array) || !(result.manifest instanceof Uint8Array))
        throw new Error("Invalid state-machine signing result");
      return { asset: result.asset, manifest: result.manifest };
    } catch (cause) { throw error(cause) }
    finally {
      this.#busy = false;
      if (this.#closed) this.requestFree();
    }
  }
  async signDetached(signer: Signer, blob: Blob): Promise<ManifestAndAssetBytes> {
    this.#runtime.assertLive();
    if (this.#closed || !this.#ffi) throw new Error("Builder has been freed");
    if (this.#busy) throw new Error("Builder already has an in-flight operation");
    validateAssetSize(blob.size, MAX_SIZE_IN_BYTES);
    this.#busy = true;
    try {
      const result: unknown = await this.#ffi.signDetached(signer, blob);
      this.#runtime.assertLive();
      if (this.#closed) throw new Error("Builder has been freed");
      if (!object(result) || !(result.asset instanceof Uint8Array) || !(result.manifest instanceof Uint8Array))
        throw new Error("Invalid state-machine detached signing result");
      return { asset: result.asset, manifest: result.manifest };
    } catch (cause) { throw error(cause) }
    finally {
      this.#busy = false;
      if (this.#closed) this.requestFree();
    }
  }
  requestFree(): void {
    this.#closed = true;
    if (!this.#busy) {
      this.#ffi?.free();
      this.#ffi = undefined;
      this.#runtime.release(this);
    }
  }
  async free(): Promise<void> { this.requestFree() }
}
