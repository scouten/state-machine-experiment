// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

// Signing a JPEG with a c2pa-rs-shaped manifest definition, where *all*
// asynchrony lives here, in JavaScript, and the Rust addon is a
// synchronous advance / fulfill / finish state machine — the write-side
// twin of ../c2pa-node-compat-addon/index.mjs.
//
// What a Node host decides here, and what a Rust-owned signer could not
// leave to it:
//   * how the source is read and the output written (here: FileHandle,
//     i.e. libuv's thread pool; but the loop does not care);
//   * how many requests are in flight at once (`concurrency`);
//   * above all, WHO HOLDS THE KEY. `signer.sign(data)` returns a Promise,
//     so the key can sit in a KMS, an HSM, or behind WebCrypto; the Rust
//     side never sees it, and the event loop keeps running while it signs.

import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import { open, rename, unlink } from "node:fs/promises";
import { basename, dirname, extname, join } from "node:path";

const native = createRequire(import.meta.url)("./index.node");

export class Builder {
  #definition;

  /** `definition` is a JSON string or a plain object; see the baseline README. */
  constructor(definition) {
    this.#definition = typeof definition === "string" ? definition : JSON.stringify(definition);
  }

  /**
   * Signs `asset` (`{ path, mimeType? }`) with `signer`
   * (`{ alg, certs: Buffer[], sign: async (data: Buffer) => Buffer }`).
   *
   * `signer.sign` receives a COSE `Sig_structure` and must resolve to the
   * raw signature COSE wants: for ECDSA, fixed-width `r || s` (in Node,
   * `crypto.sign(..., { dsaEncoding: "ieee-p1363" })`), not DER.
   *
   * With `options.output = { path }` the signed asset is built in a
   * temporary file beside it and renamed into place only on success; on
   * any failure the temporary file is removed and an existing output is
   * left untouched. Without it the signed asset is returned as
   * `result.buffer`.
   *
   * Resolves to `{ manifest, manifestStart, manifestLen, buffer? }`.
   * Rejects with the signer's own error if it rejected, or an `Error`
   * whose `name` is the Rust side's error string (e.g.
   * `Definition(BadDefinition("..."))`, `C2pa(UnsupportedType)`).
   *
   * `options`: `output`, `concurrency` (default: no limit beyond what the
   * engine itself asks for), `format` (default: sniffed, then extension).
   */
  async sign(asset, signer, options = {}) {
    const source = await openSource(asset);
    let out;
    try {
      const format =
        options.format ??
        asset.mimeType ??
        ((await sniff(source)) || (asset.path ? extname(asset.path).slice(1) : ""));
      const session = native.buildNew(this.#definition, format, signer.alg, signer.certs ?? []);
      out = await openOutput(options.output);
      const report = await drive(session, { source, out: out.target, signer }, options);
      const buffer = await out.commit();
      return buffer === undefined ? report : { ...report, buffer };
    } catch (error) {
      await out?.discard();
      throw error;
    } finally {
      await source.close();
    }
  }
}

/** `new Builder(definition).sign(asset, signer, options)`. */
export function signAsset(asset, definition, signer, options) {
  return new Builder(definition).sign(asset, signer, options);
}

// ---------------------------------------------------------------------------

async function drive(session, io, options) {
  const { concurrency = Infinity } = options;
  const queue = [];
  const inFlight = new Set();
  let failure;

  function start(request) {
    const task = answerRequest(request, io)
      .then(([kind, value]) => native.buildFulfill(session, request.id, kind, value))
      .catch((error) => (failure ??= error))
      .finally(() => inFlight.delete(task));
    inFlight.add(task);
  }

  try {
    for (;;) {
      const step = native.buildAdvance(session);
      if (step.done) break;

      queue.push(...step.requests);
      while (queue.length > 0 && inFlight.size < concurrency) start(queue.shift());

      if (inFlight.size === 0) throw new Error("c2pa session stalled: nothing in flight");
      await Promise.race(inFlight);
      if (failure) throw failure;
    }
  } finally {
    // Never leave a read, write or signature running against a handle the
    // caller is about to close and a file it is about to delete.
    await Promise.allSettled(inFlight);
  }
  if (failure) throw failure;

  const { manifest, manifestStart, manifestLen } = native.buildFinish(session);
  return { manifest, manifestStart, manifestLen };
}

/**
 * Answers one request. Rejects on any failure, so the *original* error
 * (the signer's, an `ENOSPC`) is what the caller sees.
 *
 * Exported for tests; not part of the public surface.
 */
export async function answerRequest(request, { source, out, signer }) {
  switch (request.kind) {
    case "read":
      return ["bytes", await (request.stream === "source" ? source : out).read(request.start, request.len)];
    case "length":
      return ["length", await (request.stream === "source" ? source : out).size()];
    case "write":
      await out.write(request.offset, request.bytes);
      return ["written"];
    case "sign": {
      if (request.alg !== String(signer.alg).toLowerCase()) {
        throw new Error(`signer is ${signer.alg}, the session asked for ${request.alg}`);
      }
      const signature = await signer.sign(Buffer.from(request.data));
      if (!(signature instanceof Uint8Array)) {
        throw new TypeError("signer.sign must resolve to a Buffer or Uint8Array");
      }
      return ["signature", Buffer.from(signature.buffer, signature.byteOffset, signature.byteLength)];
    }
    default:
      throw new Error(`unsupported request ${request.kind}`);
  }
}

/** Exported for tests; not part of the public surface. */
export async function openSource(asset) {
  if (!asset?.path) throw new TypeError("asset needs a path");
  const handle = await open(asset.path, "r");
  try {
    const { size } = await handle.stat();
    return {
      size: async () => size,
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
  } catch (error) {
    await handle.close();
    throw error;
  }
}

/**
 * Where the signed asset goes. `target` answers the output stream's reads,
 * length and writes; `commit()` publishes it (resolving to the bytes when
 * there is no path), `discard()` removes every trace.
 */
async function openOutput(output) {
  if (!output?.path) return openMemoryOutput();

  const dest = output.path;
  // Exclusive create (`wx`, i.e. O_EXCL: never follows a symlink or reuses
  // a file) under an unpredictable name beside the destination, so the
  // rename is on one filesystem and a failed build never touches `dest`.
  const temp = join(dirname(dest), `.${basename(dest)}.${randomBytes(8).toString("hex")}.tmp`);
  const handle = await open(temp, "wx+");
  let closed = false;
  const close = async () => {
    if (!closed) {
      closed = true;
      await handle.close();
    }
  };

  return {
    target: {
      async read(start, len) {
        const buf = Buffer.allocUnsafe(len);
        for (let got = 0; got < len; ) {
          const { bytesRead } = await handle.read(buf, got, len - got, start + got);
          if (bytesRead === 0) throw new Error(`unexpected end of output at ${start + got}`);
          got += bytesRead;
        }
        return buf;
      },
      async size() {
        return (await handle.stat()).size;
      },
      async write(offset, bytes) {
        for (let done = 0; done < bytes.length; ) {
          const { bytesWritten } = await handle.write(bytes, done, bytes.length - done, offset + done);
          done += bytesWritten;
        }
      },
    },
    async commit() {
      await close();
      await rename(temp, dest);
    },
    async discard() {
      await close().catch(() => {});
      await unlink(temp).catch(() => {});
    },
  };
}

function openMemoryOutput() {
  let buffer = Buffer.alloc(0);
  return {
    target: {
      read: async (start, len) => Buffer.from(buffer.subarray(start, start + len)),
      size: async () => buffer.length,
      async write(offset, bytes) {
        if (buffer.length < offset + bytes.length) {
          const grown = Buffer.alloc(offset + bytes.length);
          buffer.copy(grown);
          buffer = grown;
        }
        bytes.copy(buffer, offset);
      },
    },
    commit: async () => buffer,
    discard: async () => {},
  };
}

/** JPEG is the one format this build handles; recognize it from its SOI. */
async function sniff(source) {
  if ((await source.size()) < 3) return "";
  const head = await source.read(0, 3);
  return head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff ? "image/jpeg" : "";
}

/** The raw synchronous binding, exported for tests; not part of the public surface. */
export { native as _native };
