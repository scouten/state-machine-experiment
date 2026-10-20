import { Reader } from "c2pa-node-compat-addon";
import { readerSettings, validateConfig, type AdobeReadConfig } from "./config.ts";

export type { AdobeReadConfig } from "./config.ts";
export type SourceAsset = { path: string; mimeType?: string } | { buffer: Buffer; mimeType: string };

export class InvalidSourceAssetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSourceAssetError";
  }
}

/** Basic Adobe-shaped reading, with asynchronous I/O owned by the Node host. */
export class C2paReader {
  #reader: Reader;

  private constructor(reader: Reader) {
    this.#reader = reader;
  }

  static async fromAsset(asset: SourceAsset, config: AdobeReadConfig): Promise<C2paReader | null> {
    validateConfig(config);
    if (!("path" in asset) && !asset.mimeType)
      throw new InvalidSourceAssetError("mimeType is required when reading from a buffer asset.");
    const settings = readerSettings(config);
    const trust = (value: { trustAnchors?: string | string[]; userAnchors?: string | string[]; verifyTrustList?: boolean }) => ({
      ...(value.trustAnchors !== undefined ? { trust_anchors: Array.isArray(value.trustAnchors) ? value.trustAnchors.join("\n") : value.trustAnchors } : {}),
      ...(value.userAnchors !== undefined ? { user_anchors: Array.isArray(value.userAnchors) ? value.userAnchors.join("\n") : value.userAnchors } : {}),
      ...(value.verifyTrustList !== undefined ? { verify_trust_list: value.verifyTrustList } : {}),
    });
    const reader = await Reader.fromAsset(asset, {
      verify: { verify_trust: settings.verify.verifyTrust, ocsp_fetch: false },
      ...("trust" in settings ? { trust: trust(settings.trust) } : {}),
      ...(settings.cawgTrust ? { cawg_trust: trust(settings.cawgTrust) } : {}),
    });
    return reader === null ? null : new C2paReader(reader);
  }

  json() { return this.#reader.json() }
  activeLabel() { return this.#reader.activeLabel() }
  getActive() { return this.#reader.getActive() }
  remoteUrl() { return this.#reader.remoteUrl() }
  isEmbedded() { return this.#reader.isEmbedded() }
  async resourceToAsset(uri: string, asset: { buffer: Buffer | null } | { path: string }) {
    return await this.#reader.resourceToAsset(uri, asset);
  }
}
