export const protocol = "shared-worker-proof-v2";

export function failure(error) {
  return { name: error?.name ?? "Error", message: error?.message ?? String(error) };
}

export function remoteError(value) {
  const error = new Error(value.message);
  error.name = value.name;
  return error;
}

export class Client {
  #port;
  #pending = new Map();
  #next = 1;
  #closed;
  #ready;
  #termination;
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
      if (message.ready || message.ok) pending.resolve(message.value);
      else pending.reject(remoteError(message.error));
    });
    port.onError((error) => this.#fail(error));
  }
  async read(asset, { settings, now = Math.floor(Date.now() / 1000) } = {}) {
    if (this.#closed) throw this.#closed;
    if (!(asset instanceof Uint8Array)) throw new TypeError("asset must be Uint8Array");
    if (!Number.isInteger(now) || now < -2147483648 || now > 2147483647)
      throw new TypeError("proof clock must be signed 32-bit Unix seconds");
    // Snapshot before await; no transfer means caller's bytes stay attached.
    const snapshot = new Uint8Array(asset);
    const json = settings === undefined ? undefined : JSON.stringify(settings);
    await this.#ready;
    if (this.#closed) throw this.#closed;
    return this.#call({ method: "read", asset: snapshot, settings: json, now });
  }
  async sign(asset, definition, signer) {
    if (this.#closed) throw this.#closed;
    if (!(asset instanceof Uint8Array)) throw new TypeError("asset must be Uint8Array");
    if (signer?.alg !== "es256" || typeof signer.sign !== "function")
      throw new TypeError("proof signer must supply es256 and sign(data)");
    if (!Array.isArray(signer.certs) || !signer.certs.every((cert) => cert instanceof Uint8Array))
      throw new TypeError("signer certs must be Uint8Array[]");
    const snapshot = new Uint8Array(asset);
    const certs = signer.certs.map((cert) => new Uint8Array(cert));
    const json = typeof definition === "string" ? definition : JSON.stringify(definition);
    const sign = signer.sign.bind(signer);
    await this.#ready;
    if (this.#closed) throw this.#closed;
    return this.#call({ method: "build", asset: snapshot, definition: json, certs }, sign);
  }
  #call(command, sign) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject, sign, signing: false });
      try { this.#port.post({ protocol, id, ...command }) }
      catch (error) { this.#pending.delete(id); reject(error) }
    });
  }
  async #sign(message, pending) {
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
    if (this.#closed || this.#pending.get(message.id) !== pending) return;
    try {
      this.#port.post({ protocol, method: "signReply", id: message.id,
        requestId: message.requestId, ...reply });
    } catch (error) { this.#fail(error) }
  }
  #fail(error) {
    if (this.#closed) return;
    this.#closed = error;
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.#termination = Promise.resolve(this.#port.terminate());
  }
  async dispose() {
    this.#fail(new Error("Worker client disposed"));
    await this.#termination;
  }
}
