// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// The c2pa-node `Reader` API (`Reader.fromAsset`, `json`, `activeLabel`,
// `getActive`, `remoteUrl`, `isEmbedded`), where *all* asynchrony lives
// here, in JavaScript, and the Rust addon is a synchronous
// advance / fulfill / finish state machine.
//
// Nothing in this file is clever, and that is the point: it is the loop
// every sans-I/O host is. What a Node host gets to decide, and c2pa-node's
// tokio-backed addon decides for it, is:
//   * how asset bytes are read (here: FileHandle.read, i.e. libuv's thread
//     pool; but equally a network blob, a cache, an S3 range request);
//   * how many requests are in flight at once (`concurrency`);
//   * how OCSP is fetched (here: the global `fetch`; so proxies, agents,
//     and mocks are Node's business, not a reqwest feature flag's);
//   * what "now" is (`now`), which makes reads reproducible in tests.

import { createRequire } from "node:module";
import { open } from "node:fs/promises";
import { isIP } from "node:net";
import { extname } from "node:path";

const native = createRequire(import.meta.url)("./index.node");

export class Reader {
  #store;

  constructor(store) {
    this.#store = store;
  }

  /** The manifest store, as c2pa-rs's `Reader::json` reports it. */
  json() {
    return structuredClone(this.#store);
  }

  activeLabel() {
    return this.#store.active_manifest ?? undefined;
  }

  getActive() {
    const label = this.activeLabel();
    return label === undefined ? undefined : this.#store.manifests?.[label];
  }

  remoteUrl() {
    return "";
  }

  isEmbedded() {
    return true;
  }

  /**
   * Reads and validates the manifest store in `asset`.
   *
   * `asset` is `{ path, mimeType? }`, `{ buffer, mimeType? }` as in
   * c2pa-node, or `{ size, read(start, len) => Promise<Buffer>, mimeType? }`:
   * any random-access source the caller can answer asynchronously.
   *
   * Resolves to `null` if the asset carries no manifest store, as
   * c2pa-node's does. Rejects with an `Error` whose `name` is c2pa-rs's
   * `Debug` string for the failure (e.g. `C2pa(UnsupportedType)`).
   *
   * `options`:
   *   - `concurrency`: at most this many requests in flight (default: no limit
   *     beyond what the engine itself asks for, currently 8 chunk reads);
   *   - `fetch`: used for OCSP (default: global `fetch`);
   *   - `ocspPolicy`: `(url) => boolean`, whether an OCSP responder URL taken from
   *     the asset's certificate may be contacted (default: `defaultOcspPolicy`);
   *   - `now`: `() => ms since epoch` (default `Date.now`).
   */
  static async fromAsset(asset, settings, options = {}) {
    const source = await openSource(asset);
    try {
      // An explicit mime type is taken as given. Otherwise the bytes decide
      // (a JPEG named `photo.dat` is still a JPEG), and only if they are
      // not recognized does the file extension get a say.
      const format =
        asset.mimeType ??
        ((await sniff(source)) || (asset.path ? extname(asset.path).slice(1) : ""));
      const store = await readStore(
        source,
        format,
        typeof settings === "object" && settings !== null
          ? JSON.stringify(settings)
          : (settings ?? undefined),
        options,
      );
      return store === null ? null : new Reader(JSON.parse(store));
    } finally {
      await source.close();
    }
  }
}

// ---------------------------------------------------------------------------

async function readStore(source, format, settings, options) {
  const { concurrency = Infinity, now = Date.now, ocspPolicy } = options;
  const doFetch = options.fetch ?? globalThis.fetch;
  const session = native.sessionNew(format, settings);

  const answer = (request) => answerRequest(request, source, { doFetch, now, ocspPolicy });

  const queue = [];
  const inFlight = new Set();
  let failure;

  function start(request) {
    const task = answer(request)
      .then(([kind, value]) => native.sessionFulfill(session, request.id, kind, value))
      .catch((error) => (failure ??= error))
      .finally(() => inFlight.delete(task));
    inFlight.add(task);
  }

  for (;;) {
    const step = native.sessionAdvance(session);
    if (step.done) break;

    queue.push(...step.requests);
    while (queue.length > 0 && inFlight.size < concurrency) start(queue.shift());

    if (inFlight.size === 0) throw new Error("c2pa session stalled: nothing in flight");
    await Promise.race(inFlight);
    if (failure) throw failure;
  }

  return native.sessionFinish(session);
}

const MAX_OCSP_RESPONSE = 1 << 20;

/**
 * The default answer to "may this OCSP responder URL be contacted?":
 * `http` or `https`, no embedded credentials, and not a literal loopback,
 * private, link-local, or `localhost` address.
 *
 * This stops the obvious case of a certificate naming an internal address.
 * It cannot stop a *name* that resolves to one: that needs control at the
 * resolver, which is what the injectable `fetch` option is for (e.g. an
 * undici dispatcher whose `lookup` rejects private addresses). A server
 * reading untrusted assets with `verify.ocsp_fetch` on should do that, or
 * leave `ocsp_fetch` off, its default.
 */
export function defaultOcspPolicy(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  if (parsed.username || parsed.password) return false;

  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return false;

  switch (isIP(host)) {
    case 4: {
      const [a, b] = host.split(".").map(Number);
      return !(
        a === 0 || a === 10 || a === 127 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168)
      );
    }
    case 6: {
      // `new URL` normalizes an IPv4-mapped address to its hex form
      // (`::ffff:7f00:1`); judge it as the IPv4 address it stands for.
      const mapped = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (mapped) {
        const [hi, lo] = [parseInt(mapped[1], 16), parseInt(mapped[2], 16)];
        return defaultOcspPolicy(`http://${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}/`);
      }
      return !(
        host === "::" || host === "::1" ||
        /^f[cd]/.test(host) ||      // fc00::/7 unique local
        /^fe[89ab]/.test(host)      // fe80::/10 link local
      );
    }
    default:
      return true;
  }
}

/**
 * Answers one request from the engine. Never rejects: whatever the host
 * cannot do becomes a `failed` reply, which the engine interprets
 * (fail-open for OCSP, a hard error for an unreadable asset).
 *
 * Exported for tests; not part of the c2pa-node surface.
 */
export async function answerRequest(
  request,
  source,
  { doFetch, now, ocspPolicy = defaultOcspPolicy },
) {
  try {
    switch (request.kind) {
      case "read":
        return ["bytes", await source.read(request.start, request.len)];
      case "length":
        return ["length", source.size];
      case "time":
        return ["time", Math.floor(now() / 1000)];
      case "ocsp": {
        // The URL comes from the *asset's* certificate, i.e. from whoever
        // made the asset: it is untrusted input.
        if (!ocspPolicy(request.url)) {
          return ["failed", `OCSP responder ${request.url} refused by policy`];
        }
        const response = await doFetch(request.url, {
          method: "POST",
          headers: { "content-type": "application/ocsp-request" },
          body: request.requestDer,
          // A permitted responder must not bounce the request somewhere
          // the policy would not have permitted.
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) return ["failed", `OCSP responder said ${response.status}`];
        const body = Buffer.from(await response.arrayBuffer());
        if (body.length > MAX_OCSP_RESPONSE) return ["failed", "OCSP response too large"];
        return ["ocsp", body];
      }
      default:
        return ["failed", `unsupported request ${request.kind}`];
    }
  } catch (error) {
    return ["failed", String(error?.message ?? error)];
  }
}

/** Exported for tests; not part of the c2pa-node surface. */
export async function openSource(asset) {
  if (typeof asset?.read === "function") {
    return { size: asset.size, read: asset.read, close: async () => {} };
  }

  if (asset?.buffer) {
    const buffer = asset.buffer;
    return {
      size: buffer.length,
      read: async (start, len) => buffer.subarray(start, start + len),
      close: async () => {},
    };
  }

  if (asset?.path) {
    const handle = await open(asset.path, "r");
    // Close the handle if it cannot even be measured.
    const { size } = await handle.stat().catch((e) => handle.close().then(() => Promise.reject(e)));
    return {
      size,
      async read(start, len) {
        const out = Buffer.allocUnsafe(len);
        for (let got = 0; got < len; ) {
          const { bytesRead } = await handle.read(out, got, len - got, start + got);
          if (bytesRead === 0) throw new Error(`unexpected end of file at ${start + got}`);
          got += bytesRead;
        }
        return out;
      },
      close: () => handle.close(),
    };
  }

  throw new TypeError("asset needs a path, a buffer, or read/size");
}

/** JPEG is the one format this build handles; recognize it from its SOI. */
async function sniff(source) {
  if (source.size < 3) return "";
  const head = await source.read(0, 3);
  return head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff ? "image/jpeg" : "";
}

/** The raw synchronous binding, exported for tests; not part of the c2pa-node surface. */
export { native as _native };
