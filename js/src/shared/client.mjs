import { abortError, throwIfAborted, validateSignal } from "./cancellation.mjs";

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
  #idleWaiters = new Set();
  /** @param {Port} port */
  constructor(port) {
    this.#port = port;
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
      if (pending.onAbort) pending.signal.removeEventListener("abort", pending.onAbort);
      this.#notifyIdle();
      if (!pending.cancelled) {
        if (message.ready || message.ok) pending.resolve(message.value);
        else pending.reject(remoteError(message.error));
      }
    });
    port.onError((error) => this.#fail(error));
  }
  /**
   * Reads and validates an asset.
   * @param {Uint8Array} asset Copied synchronously, before any await.
   * @param {{settings?: object, now?: number, signal?: AbortSignal}} [options] `now` is Unix seconds
   *   (signed 32-bit) used as the validation clock; defaults to the current time.
   * @returns {Promise<{report: object|null, stats: object, workerMs: number}>}
   */
  async read(asset, { settings, now = Math.floor(Date.now() / 1000), signal } = {}) {
    if (this.#closed) throw this.#closed;
    validateSignal(signal);
    throwIfAborted(signal);
    if (!(asset instanceof Uint8Array)) throw new TypeError("asset must be Uint8Array");
    if (!Number.isInteger(now) || now < -2147483648 || now > 2147483647)
      throw new TypeError("proof clock must be signed 32-bit Unix seconds");
    // Snapshot before await; no transfer means caller's bytes stay attached.
    const snapshot = new Uint8Array(asset);
    const json = settings === undefined ? undefined : JSON.stringify(settings);
    await this.#awaitReady(signal);
    if (this.#closed) throw this.#closed;
    throwIfAborted(signal);
    return this.#call({ method: "read", asset: snapshot, settings: json, now }, undefined, signal);
  }
  /**
   * Signs an asset with a manifest built from `definition`.
   * @param {Uint8Array} asset Copied synchronously, before any await.
   * @param {object|string} definition Manifest definition (object or JSON).
   * @param {{alg: "es256", certs: Uint8Array[], sign(data: Uint8Array): Promise<Uint8Array>|Uint8Array}} signer
   *   Runs on the caller's thread; its key never leaves it.
   * @param {{signal?: AbortSignal}} [options]
   */
  async sign(asset, definition, signer, { signal } = {}) {
    if (this.#closed) throw this.#closed;
    validateSignal(signal);
    throwIfAborted(signal);
    if (!(asset instanceof Uint8Array)) throw new TypeError("asset must be Uint8Array");
    if (signer?.alg !== "es256" || typeof signer.sign !== "function")
      throw new TypeError("proof signer must supply es256 and sign(data)");
    if (!Array.isArray(signer.certs) || !signer.certs.every((cert) => cert instanceof Uint8Array))
      throw new TypeError("signer certs must be Uint8Array[]");
    const snapshot = new Uint8Array(asset);
    const certs = signer.certs.map((cert) => new Uint8Array(cert));
    const json = typeof definition === "string" ? definition : JSON.stringify(definition);
    const sign = signer.sign.bind(signer);
    await this.#awaitReady(signal);
    if (this.#closed) throw this.#closed;
    throwIfAborted(signal);
    return this.#call({ method: "build", asset: snapshot, definition: json, certs }, sign, signal);
  }
  async #awaitReady(signal) {
    if (!signal) return this.#ready;
    throwIfAborted(signal);
    let onAbort;
    try {
      await new Promise((resolve, reject) => {
        onAbort = () => reject(abortError(signal));
        signal.addEventListener("abort", onAbort, { once: true });
        if (signal.aborted) onAbort();
        this.#ready.then(resolve, reject);
      });
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
  }
  /** Posts a command and registers its pending entry; `sign` is the optional signer callback. */
  #call(command, sign, signal) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const pending = { resolve, reject, sign, signing: false, cancelled: false, signal, onAbort: undefined };
      this.#pending.set(id, pending);
      if (signal) {
        pending.onAbort = () => {
          if (pending.cancelled || this.#pending.get(id) !== pending) return;
          pending.cancelled = true;
          const error = abortError(signal);
          pending.sign = undefined;
          signal.removeEventListener("abort", pending.onAbort);
          pending.onAbort = undefined;
          pending.signal = undefined;
          try { this.#port.post({ protocol, method: "cancel", id }) }
          catch (postError) { this.#fail(postError); return }
          reject(error);
        };
        signal.addEventListener("abort", pending.onAbort, { once: true });
      }
      try {
        this.#port.post({ protocol, id, ...command });
        if (signal?.aborted) pending.onAbort();
      } catch (error) {
        this.#pending.delete(id);
        if (pending.onAbort) signal.removeEventListener("abort", pending.onAbort);
        reject(error);
      }
    });
  }
  /** Runs the caller's signer for a Worker `sign` message and posts the `signReply`. */
  async #sign(message, pending) {
    if (pending.cancelled) return;
    if (!pending.sign || pending.signing || message.alg !== "es256" ||
        !(message.data instanceof Uint8Array) || !Number.isSafeInteger(message.requestId) ||
        message.requestId < 0) {
      this.#fail(new Error("invalid Worker signer request"));
      return;
    }
    pending.signing = true;
    let reply;
    try {
      const value = await pending.sign(message.data);
      if (!(value instanceof Uint8Array) || value.length !== 64)
        throw new TypeError("es256 signer must return 64 raw signature bytes");
      reply = { ok: true, value: new Uint8Array(value) };
    } catch (error) {
      reply = { ok: false, error: failure(error) };
    }
    pending.signing = false;
    // Disposal cannot cancel caller-owned signing. Consume its late result,
    // but never post it to a terminated Worker or a different operation.
    if (this.#closed || pending.cancelled || this.#pending.get(message.id) !== pending) return;
    try {
      this.#port.post({ protocol, method: "signReply", id: message.id,
        requestId: message.requestId, ...reply });
    } catch (error) { this.#fail(error) }
  }
  /** Fails every pending call with `error` and terminates the Worker. Idempotent. */
  #fail(error) {
    if (this.#closed) return;
    this.#closed = error;
    for (const pending of this.#pending.values()) {
      if (pending.onAbort) pending.signal.removeEventListener("abort", pending.onAbort);
      pending.reject(error);
    }
    this.#pending.clear();
    this.#notifyIdle();
    this.#termination = Promise.resolve(this.#port.terminate());
  }
  /** The terminal error once the client has failed or been disposed, else `undefined`. */
  get failure() { return this.#closed }
  /** Resolves when every posted command has received a terminal Worker reply. */
  whenIdle() {
    if (![...this.#pending.keys()].some((id) => id !== 0)) return Promise.resolve();
    return new Promise((resolve) => this.#idleWaiters.add(resolve));
  }
  #notifyIdle() {
    if ([...this.#pending.keys()].some((id) => id !== 0)) return;
    for (const resolve of this.#idleWaiters) resolve();
    this.#idleWaiters.clear();
  }
  /** Rejects outstanding calls, terminates the Worker and waits for it to stop. */
  async dispose() {
    this.#fail(new Error("Worker client disposed"));
    await this.#termination;
  }
}
