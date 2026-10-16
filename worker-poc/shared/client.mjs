export const protocol = "shared-reader-proof-v1";

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
      this.#pending.delete(id);
      if (message.ready || message.ok) pending.resolve(message.value);
      else {
        const error = new Error(message.error.message);
        error.name = message.error.name;
        pending.reject(error);
      }
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
    const id = this.#next++;
    return await new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try { this.#port.post({ protocol, id, method: "read", asset: snapshot, settings: json, now }) }
      catch (error) { this.#pending.delete(id); reject(error) }
    });
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
