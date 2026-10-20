import { createC2pa as createInline, type Config, type Reader } from "c2pa-js-state-machine/inline";
import { createC2pa as createWorker } from "c2pa-js-state-machine/worker";
import { readerSettings, validateConfig, type AdobeReadConfig } from "./config.ts";

export type { AdobeReadConfig } from "./config.ts";
export interface AdobeC2paConfig extends AdobeReadConfig {
  wasmSrc: Config["wasmSrc"];
  workerSrc?: URL;
}

type ReaderBackend = Pick<Reader,
  "activeLabel" | "activeManifest" | "manifestStore" | "json" | "resourceToBytes" | "free">;

/** The basic read surface only; AI/model helpers are a later vertical slice. */
export class AdobeReader {
  #reader: ReaderBackend;

  constructor(reader: ReaderBackend) {
    this.#reader = reader;
  }

  async activeLabel() { return await this.#reader.activeLabel() }
  async activeManifest() { return await this.#reader.activeManifest() }
  async manifestStore() { return await this.#reader.manifestStore() }
  async json() { return await this.#reader.json() }
  async resourceToBytes(uri: string) { return await this.#reader.resourceToBytes(uri) }
  async free() { await this.#reader.free() }
}

/** Creates a read-only facade. No signing or service API is implied. */
export async function createAdobeC2pa(config: AdobeC2paConfig) {
  validateConfig(config, true);
  const settings = readerSettings(config);
  const runtime = config.workerSrc === undefined
    ? await createInline({ wasmSrc: config.wasmSrc, settings })
    : await createWorker({ wasmSrc: config.wasmSrc, workerSrc: config.workerSrc, settings });
  return {
    reader: {
      async fromBlob(mimeType: string, blob: Blob): Promise<AdobeReader | null> {
        const reader = await runtime.reader.fromBlob(mimeType, blob);
        return reader === null ? null : new AdobeReader(reader);
      },
    },
    get liveResources() { return runtime.liveResources },
    dispose() { runtime.dispose() },
  };
}
