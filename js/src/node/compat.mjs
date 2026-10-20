import { X509Certificate } from "node:crypto";
import { createClient } from "./client.mjs";

function object(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(`${name} must be an object`);
}

function keys(value, allowed, name) {
  object(value, name);
  for (const key of Object.keys(value))
    if (!allowed.includes(key)) throw new TypeError(`unsupported ${name}.${key}`);
}

function assetSource(asset) {
  keys(asset, ["path", "buffer", "mimeType"], "asset");
  if (asset.mimeType !== undefined && !["image/jpeg", "jpeg", "jpg"].includes(asset.mimeType))
    throw new TypeError("compatibility slice supports only JPEG");
  if (("path" in asset) === ("buffer" in asset))
    throw new TypeError("asset must supply exactly one of path or buffer");
  if ("path" in asset) return { path: asset.path };
  if (!Buffer.isBuffer(asset.buffer)) throw new TypeError("asset.buffer must be a Buffer");
  return asset.buffer;
}

function buffer(bytes) {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export class Context {
  constructor(settings = {}) { this.settings = structuredClone(settings) }
}

function readSettings(value) {
  const settings = value instanceof Context ? value.settings : value ?? {};
  keys(settings, ["trust", "verify"], "settings");
  const trust = settings.trust ?? {};
  keys(trust, ["userAnchors"], "trust");
  if (trust.userAnchors !== undefined && typeof trust.userAnchors !== "string")
    throw new TypeError("trust.userAnchors must be inline PEM text");
  const verify = settings.verify ?? {};
  const supported = { ocspFetch: false, remoteManifestFetch: false,
    verifyAfterReading: true, verifyTrust: true, verifyAfterSign: false };
  keys(verify, Object.keys(supported), "verify");
  for (const [key, value] of Object.entries(verify))
    if (value !== supported[key]) throw new TypeError(`unsupported verify.${key}=${value}`);
  return { trust: { user_anchors: trust.userAnchors ?? "" }, verify: { ocsp_fetch: false } };
}

export class CallbackSigner {
  #config;
  #callback;
  #certs;
  constructor(config, callback) {
    keys(config, ["alg", "certs", "reserveSize", "directCoseHandling"], "signer");
    if (config.alg !== "es256" || config.directCoseHandling !== false ||
        config.reserveSize !== 10000 || typeof callback !== "function")
      throw new TypeError("compatibility signer requires es256, raw signatures, reserveSize 10000 and a callback");
    if (!Array.isArray(config.certs) || !config.certs.length ||
        !config.certs.every(Buffer.isBuffer))
      throw new TypeError("signer.certs must be PEM Buffer[]");
    this.#certs = config.certs.flatMap((pem) => {
      const blocks = pem.toString("utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
      if (!blocks?.length) throw new TypeError("signer.certs must contain PEM certificates");
      return blocks.map((block) => new X509Certificate(block).raw);
    });
    this.#config = { ...config, certs: config.certs.map((cert) => Buffer.from(cert)) };
    this.#callback = callback;
  }
  static newSigner(config, callback) { return new CallbackSigner(config, callback) }
  alg() { return this.#config.alg }
  certs() { return Array.from(Buffer.concat(this.#config.certs)) }
  reserveSize() { return this.#config.reserveSize }
  directCoseHandling() { return false }
  timeAuthorityUrl() { return undefined }
  async sign(bytes) { return this.#callback(bytes) }
  workerSigner() {
    return { alg: "es256", certs: this.#certs,
      sign: (bytes) => this.sign(buffer(bytes)) };
  }
}

export function createNodeCompat() {
  const client = createClient();
  class Reader {
    #report;
    constructor(report) { this.#report = structuredClone(report) }
    static async fromAsset(asset, context) {
      const settings = readSettings(context);
      const result = await client.read(assetSource(asset), { settings });
      return result.report === null ? null : new Reader(result.report);
    }
    json() { return structuredClone(this.#report) }
    activeLabel() { return this.#report.active_manifest ?? undefined }
    getActive() { return this.json().manifests?.[this.activeLabel()] }
  }
  class Builder {
    #definition;
    constructor(definition) { this.#definition = structuredClone(definition) }
    static async withJsonAsync(definition, context) {
      readSettings(context);
      return new Builder(definition);
    }
    async signAsync(signer, asset, destination) {
      if (!(signer instanceof CallbackSigner)) throw new TypeError("expected compatibility CallbackSigner");
      keys(destination, ["path", "buffer"], "destination");
      if (("path" in destination) === ("buffer" in destination))
        throw new TypeError("destination must supply exactly one of path or buffer");
      if ("buffer" in destination && destination.buffer !== null && !Buffer.isBuffer(destination.buffer))
        throw new TypeError("destination.buffer must be null or Buffer");
      const buffered = "buffer" in destination;
      const result = await client.sign(assetSource(asset), this.#definition, signer.workerSigner(),
        buffered ? undefined : { path: destination.path });
      if (buffered) destination.buffer = buffer(result.asset);
      return buffer(result.manifest);
    }
  }
  return { Reader, Builder, CallbackSigner, Context, dispose: () => client.dispose() };
}
