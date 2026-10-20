/**
 * A fixed-size pool of {@link Client}s, one Worker each.
 *
 * Sessions are not thread-safe and never leave the Worker that created them,
 * so parallelism comes only from running separate calls on separate Workers.
 * Workers are interchangeable generalists: the session type (read or build)
 * is chosen per call by the command, so no Worker is specialized at startup.
 * A call is bound to one Worker for its whole life; its signing callbacks
 * stay on the caller's side exactly as with a single Client.
 */

/** Largest accepted pool size; each Worker holds its own Wasm/addon state and buffers. */
export const MAX_WORKERS = 64;

export class ClientPool {
  #create;
  #clients = [];
  /** Calls in flight per client, for least-loaded dispatch. */
  #load = new Map();
  #disposed = false;

  /**
   * @param {() => import("./client.mjs").Client} create Starts one Worker client.
   * @param {{workers?: number}} [options] Pool size, 1..{@link MAX_WORKERS}.
   */
  constructor(create, { workers = 1 } = {}) {
    if (!Number.isInteger(workers) || workers < 1 || workers > MAX_WORKERS)
      throw new RangeError(`workers must be an integer from 1 to ${MAX_WORKERS}`);
    this.#create = create;
    for (let i = 0; i < workers; i++) this.#clients.push(this.#spawn());
  }

  get workers() { return this.#clients.length }

  #spawn() {
    const client = this.#create();
    this.#load.set(client, 0);
    return client;
  }

  /**
   * The least-loaded live client. A client that failed (its Worker died) is
   * replaced here, so one crash costs only its own in-flight calls.
   */
  #pick() {
    if (this.#disposed) throw new Error("Worker client disposed");
    let best;
    for (let i = 0; i < this.#clients.length; i++) {
      if (this.#clients[i].failure) {
        this.#load.delete(this.#clients[i]);
        this.#clients[i] = this.#spawn();
      }
      const client = this.#clients[i];
      if (best === undefined || this.#load.get(client) < this.#load.get(best)) best = client;
    }
    return best;
  }

  /** Runs `call` on one client, tracking its load. */
  async #run(call) {
    const client = this.#pick();
    this.#load.set(client, this.#load.get(client) + 1);
    try { return await call(client) }
    finally { if (this.#load.has(client)) this.#load.set(client, this.#load.get(client) - 1) }
  }

  /** See {@link Client#read}. The asset is captured synchronously by the chosen client. */
  read(...args) {
    return this.#run((client) => client.read(...args));
  }

  /** See {@link Client#sign}. */
  sign(...args) {
    return this.#run((client) => client.sign(...args));
  }

  /** Terminates every Worker; outstanding calls reject. */
  async dispose() {
    this.#disposed = true;
    await Promise.all(this.#clients.map((client) => client.dispose()));
  }
}
