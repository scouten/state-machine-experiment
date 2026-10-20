import { algorithms, checkSignature } from "./drive.mjs";

/**
 * Main-thread side of the Worker protocol, shared by Node and browsers.
 *
 * A {@link Client} sends `read`/`build` commands to a Worker running
 * `serve()` (see service.mjs) and matches replies by id. It owns the
 * caller's signer: signing requests come back from the Worker as `sign`
 * messages, run here, and return as `signReply`, so private keys and async
 * signing (KMS, WebCrypto, HSM) never enter the Worker.
 * Any protocol violation or Worker error is fatal: every pending call is
 * rejected and the Worker terminated.
 *
 * @typedef {object} Port Transport abstraction over `Worker`/`worker_threads`.
 * @property {(message: object) => void} post
 * @property {(handler: (message: object) => void) => void} onMessage
 * @property {(handler: (error: Error) => void) => void} onError
 * @property {() => unknown} terminate
 */

/** Wire-protocol version; both ends reject any other value. */
export const protocol = "shared-worker-proof-v2";

/** Serializes an error for the wire (structured clone drops prototypes). */
export function failure(error) {
  return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
}

/** Rebuilds an Error from {@link failure} output. */
export function remoteError(value) {
  const error = new Error(value.message);
  error.name = value.name;
  return error;
}

/** Copies a `Uint8Array` so later caller mutation cannot change an in-flight request; a `Blob` is immutable. */
export function snapshotAsset(asset) {
  if (asset instanceof Uint8Array) return new Uint8Array(asset);
  if (asset instanceof Blob) return asset;
  throw new TypeError("asset must be Uint8Array, Blob or File");
}

/**
 * Main-thread handle for one Worker. Methods queue commands to the Worker's
 * `serve()` loop and resolve with its replies; any protocol violation or
 * Worker error fails every outstanding call and the client.
 */
export class Client {
  #port;
  /** Calls awaiting replies by id. Id 0 is the Worker's `ready` handshake. */
  #pending = new Map();
  #next = 1;
  /** Set to the terminal error once the client is failed or disposed. */
  #closed;
  #ready;
  #termination;
  #snapshot;
  #destination;
  constructor(port, snapshot = snapshotAsset, destination = () => {
    throw new TypeError("file destinations require the Node client");
  }) {
    this.#port = port;
    this.#snapshot = snapshot;
    this.#destination = destination;
    this.#ready = new Promise((resolve, reject) => {
      this.#pending.set(0, { resolve, reject });
    });
    // Startup failures must not become unhandled rejections before read().
    this.#ready.catch(() => {});
    port.onMessage((message) => {
      if (message.protocol !== protocol) return this.#fail(new Error("invalid Worker protocol"));
      const id = message.ready ? 0 : message.id;
      const pending = this.#pending.get(id);
      if (!pending) return this.#fail(new Error("unexpected Worker reply"));
      if (message.method === "sign") {
        void this.#sign(message, pending);
        return;
      }
      this.#pending.delete(id);
      if (message.ready || message.ok) pending.resolve(message.value);
      else pending.reject(remoteError(message.error));
    });
    port.onError((error) => this.#fail(error));
  }
  /**
   * Reads and validates an asset.
   * @param {Uint8Array} asset Copied synchronously, before any await.
   * @param {{settings?: object, now?: number}} [options] `now` is Unix seconds
   *   (signed 32-bit) used as the validation clock; defaults to the current time.
   * @returns {Promise<{report: object|null, stats: object, workerMs: number}>}
   */
  async read(asset, { settings, now = Math.floor(Date.now() / 1000) } = {}) {
    if (this.#closed) throw this.#closed;
    if (!Number.isInteger(now) || now < -2147483648 || now > 2147483647)
      throw new TypeError("proof clock must be signed 32-bit Unix seconds");
    // Snapshot before await; no transfer means caller's bytes stay attached.
    const snapshot = this.#snapshot(asset);
    const json = settings === undefined ? undefined : JSON.stringify(settings);
    await this.#ready;
    if (this.#closed) throw this.#closed;
    return this.#call({ method: "read", asset: snapshot, settings: json, now });
  }
  /**
   * Signs an asset with a manifest built from `definition`.
   * @param {Uint8Array} asset Copied synchronously, before any await.
   * @param {object|string} definition Manifest definition (object or JSON).
   * @param {{alg: "es256", certs: Uint8Array[], sign(data: Uint8Array): Promise<Uint8Array>|Uint8Array}} signer
   *   Runs on the caller's thread; its key never leaves it.
   * @param {*} [destination] Node file destination, when supported.
   */
  async sign(asset, definition, signer, destination) {
    if (this.#closed) throw this.#closed;
    if (!algorithms.has(signer?.alg) || typeof signer.sign !== "function")
      throw new TypeError(`proof signer must supply sign(data) and one of: ${[...algorithms].join(", ")}`);
    if (!Array.isArray(signer.certs) || !signer.certs.every((cert) => cert instanceof Uint8Array))
      throw new TypeError("signer certs must be Uint8Array[]");
    const snapshot = this.#snapshot(asset);
    const output = destination === undefined ? undefined : this.#destination(destination);
    const certs = signer.certs.map((cert) => new Uint8Array(cert));
    const json = typeof definition === "string" ? definition : JSON.stringify(definition);
    const sign = signer.sign.bind(signer);
    await this.#ready;
    if (this.#closed) throw this.#closed;
    return this.#call({ method: "build", asset: snapshot, definition: json, certs, destination: output, alg: signer.alg }, sign);
  }
  /** Posts a command and registers its pending entry; `sign` is the optional signer callback. */
  #call(command, sign) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject, sign, signing: false });
      try { this.#port.post({ protocol, id, ...command }) }
      catch (error) { this.#pending.delete(id); reject(error) }
    });
  }
  /** Runs the caller's signer for a Worker `sign` message and posts the `signReply`. */
  async #sign(message, pending) {
    if (!pending.sign || pending.signing || !algorithms.has(message.alg) ||
        !(message.data instanceof Uint8Array) || !Number.isSafeInteger(message.requestId) ||
        message.requestId < 0) {
      this.#fail(new Error("invalid Worker signer request"));
      return;
    }
    pending.signing = true;
    let reply;
    try {
      const value = await pending.sign(message.data);
      checkSignature(message.alg, value);
      reply = { ok: true, value: new Uint8Array(value) };
    } catch (error) {
      reply = { ok: false, error: failure(error) };
    }
    pending.signing = false;
    // Disposal cannot cancel caller-owned signing. Consume its late result,
    // but never post it to a terminated Worker or a different operation.
    if (this.#closed || this.#pending.get(message.id) !== pending) return;
    try {
      this.#port.post({ protocol, method: "signReply", id: message.id,
        requestId: message.requestId, ...reply });
    } catch (error) { this.#fail(error) }
  }
  /** Fails every pending call with `error` and terminates the Worker. Idempotent. */
  #fail(error) {
    if (this.#closed) return;
    this.#closed = error;
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#termination = Promise.resolve(this.#port.terminate());
  }
  /** Rejects outstanding calls, terminates the Worker and waits for it to stop. */
  async dispose() {
    this.#fail(new Error("Worker client disposed"));
    await this.#termination;
  }
}
