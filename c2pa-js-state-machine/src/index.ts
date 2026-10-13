import init, { BrowserBuilder, BrowserReader } from "../.cache/generated/state_machine.js";
import { Context, validateAssetSize, type Settings } from "@contentauth/c2pa-utilities";

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
function isProjection(value: unknown): value is ManifestProjection {
  return object(value) && object(value.manifests) &&
    (value.validation_state === "Trusted" || value.validation_state === "Valid" || value.validation_state === "Invalid") &&
    (value.active_manifest === undefined || typeof value.active_manifest === "string") &&
    (value.validation_status === undefined || (Array.isArray(value.validation_status) &&
      value.validation_status.every((status: unknown) => object(status) && typeof status.code === "string" &&
        (status.url === undefined || typeof status.url === "string") &&
        (status.explanation === undefined || typeof status.explanation === "string"))));
}
async function contextJson(context?: Context): Promise<string | undefined> {
  if (!context) return undefined;
  const settings: unknown = context.settings ?? {};
  if (!object(settings)) throw new Error("Invalid Context");
  if (settings.trust !== undefined && (!object(settings.verify) || settings.verify.verifyTrust !== true))
    throw new Error("M1 trust anchors require verifyTrust: true");
  for (const [section, value] of Object.entries(settings)) {
    if (!["trust", "verify"].includes(section) || !object(value))
      throw new Error(`Unsupported M1 setting: ${section}`);
    for (const [key, field] of Object.entries(value)) {
      const supported = (section === "trust" && key === "trustAnchors" && typeof field === "string" &&
        field.trimStart().startsWith("-----BEGIN CERTIFICATE-----")) ||
        (section === "verify" && key === "ocspFetch" && field === false) ||
        (section === "verify" && key === "verifyTrust" && field === true);
      if (!supported) throw new Error(`Unsupported M1 setting: ${section}.${key}`);
    }
  }
  return context.toJson();
}

let source: Config["wasmSrc"] | undefined;
let loading: Promise<void> | undefined;
export async function createC2pa(config: Config): Promise<Runtime> {
  if (Object.keys(config).some((key) => !["wasmSrc", "workerSrc", "settings"].includes(key)))
    throw new Error("Unsupported M1 loader configuration");
  if (config.workerSrc !== undefined || config.settings !== undefined)
    throw new Error("M1 is inline-only; Worker configuration and global settings are not supported");
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
  return new Runtime();
}

interface Resource { requestFree(): void }
class Runtime {
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
    fromBlob: (format: string, blob: Blob, settings?: Settings) =>
      Reader.fromBlob(this, format, blob, settings ? new Context(settings) : undefined),
  };
  builder = {
    fromDefinition: (definition: Record<string, unknown>) => Builder.fromDefinition(this, definition),
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
  static async fromBlob(runtime: Runtime, format: string | undefined, blob: Blob, context?: Context): Promise<Reader | null> {
    runtime.assertLive();
    validateAssetSize(blob.size, MAX_SIZE_IN_BYTES);
    if (!format) {
      const bytes = new Uint8Array(await blob.slice(0, 3).arrayBuffer());
      if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) format = "image/jpeg";
      else throw new Error("Unsupported M1 asset format");
    }
    const json = await contextJson(context);
    runtime.assertLive();
    let ffi: BrowserReader;
    try { ffi = await BrowserReader.fromBlob(format, blob, json) }
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
  async manifestStore(): Promise<ManifestProjection> { return projection(this.#handle().manifestStore()) }
  async json(): Promise<ManifestProjection> { return projection(JSON.parse(this.#handle().json()) as unknown) }
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
