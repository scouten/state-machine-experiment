/**
 * Shared host loops that drive the synchronous Rust sessions.
 *
 * A session never performs I/O: it parks on `advance()` with a list of
 * requests, and these loops answer them (reads, lengths, writes, signatures)
 * then call `fulfill`. The same code runs in the Node Worker and the browser
 * Worker; only the `adapter` (Neon vs Wasm) differs.
 */

import { openSource, range } from "./source.mjs";

/**
 * Runs a read/validation session to completion. Requests in one step are
 * independent, so they are answered concurrently.
 * @param {{create(settings?: string): object}} adapter Session factory (Neon or Wasm).
 * @param {Uint8Array|Blob} asset
 * @param {string|undefined} settings JSON reader settings.
 * @param {number} now Unix seconds supplied as the session's clock.
 * @returns {Promise<{report: object|null, stats: object}>} Parsed report
 *   (`null` when the asset has no manifest store) and request counters.
 */
export async function read(adapter, asset, settings, now, source = openSource(asset)) {
  const session = adapter.create(settings);
  const stats = { reads: 0, bytes: 0, maxReadBytes: 0, maxReadEnd: 0,
    sourceLength: source.length, advances: 0 };
  try {
    for (;;) {
      stats.advances++;
      const step = session.advance();
      if (step.done) {
        const json = session.finish();
        return { report: json == null ? null : JSON.parse(json), stats };
      }
      if (!step.requests.length) throw new Error("session stalled without host requests");
      // The same host loop and byte-range policy run in both environments.
      const replies = await Promise.allSettled(step.requests.map(async (request) => {
        switch (request.kind) {
          case "read": {
            const { start, len } = request;
            const bytes = await source.read(start, len);
            stats.reads++;
            stats.bytes += bytes.length;
            stats.maxReadBytes = Math.max(stats.maxReadBytes, bytes.length);
            stats.maxReadEnd = Math.max(stats.maxReadEnd, start + bytes.length);
            session.fulfill(request.id, "bytes", bytes);
            break;
          }
          case "length": session.fulfill(request.id, "length", source.length); break;
          case "time": session.fulfill(request.id, "time", now); break;
          default: throw new Error(`unsupported host request: ${request.kind}`);
        }
      }));
      const failed = replies.find((reply) => reply.status === "rejected");
      if (failed) throw failed.reason;
    }
  } finally { session.close() }
}

/**
 * Runs a build-and-sign session to completion. Requests are answered
 * sequentially: the builder's two passes depend on earlier writes. Source and
 * output are addressed by stream name; the output grows in memory.
 * @param {{createBuild(definition: string, certs: Uint8Array[]): object}} adapter
 * @param {Uint8Array|Blob} asset Asset to sign.
 * @param {string} definition JSON manifest definition.
 * @param {Uint8Array[]} certs DER certificate chain, leaf first.
 * @param {(request: {id: number, alg: string, data: Uint8Array}) => Promise<Uint8Array>} sign
 *   Produces a raw ES256 signature over `request.data`.
 * @returns {Promise<object>} Builder report plus the signed `asset` and `stats`.
 */
export async function build(adapter, asset, definition, certs, sign, source = openSource(asset)) {
  const session = adapter.createBuild(definition, certs);
  let output = new Uint8Array(0);
  /** Logical output length; `output` may be larger (geometric growth). */
  let length = 0;
  const stats = { reads: 0, bytes: 0, writes: 0, writtenBytes: 0, signs: 0, advances: 0,
    sourceReads: 0, sourceBytes: 0, sourceMaxReadBytes: 0, sourceMaxReadEnd: 0,
    sourceLength: source.length };
  /** Maps a request's stream name to its backing bytes. */
  function stream(name) {
    if (name === "source") return source;
    if (name === "output") return output.subarray(0, length);
    throw new Error(`unsupported stream: ${name}`);
  }
  try {
    for (;;) {
      stats.advances++;
      const step = session.advance();
      if (step.done) {
        const report = session.finish();
        return { ...report, asset: output.slice(0, length), stats }; // trimmed copy: no stale tail
      }
      if (!step.requests.length) throw new Error("session stalled without host requests");
      for (const request of step.requests) {
        switch (request.kind) {
          case "read": {
            let bytes;
            if (request.stream === "source") {
              bytes = await source.read(request.start, request.len);
              stats.sourceReads++;
              stats.sourceBytes += bytes.length;
              stats.sourceMaxReadBytes = Math.max(stats.sourceMaxReadBytes, bytes.length);
              stats.sourceMaxReadEnd = Math.max(stats.sourceMaxReadEnd, request.start + bytes.length);
            } else {
              const output = stream(request.stream);
              range(request.start, request.len, output.length);
              bytes = output.subarray(request.start, request.start + request.len);
            }
            stats.reads++;
            stats.bytes += request.len;
            session.fulfill(request.id, "bytes", bytes);
            break;
          }
          case "length": session.fulfill(request.id, "length", stream(request.stream).length); break;
          case "write": {
            if (request.stream !== "output" || !(request.bytes instanceof Uint8Array))
              throw new Error("invalid output write");
            range(request.offset, request.bytes.length, Number.MAX_SAFE_INTEGER);
            const end = request.offset + request.bytes.length;
            if (end > output.length) {
              const next = new Uint8Array(Math.max(end, output.length * 2, 4096));
              next.set(output);
              output = next;
            }
            output.set(request.bytes, request.offset);
            length = Math.max(length, end);
            stats.writes++;
            stats.writtenBytes += request.bytes.length;
            session.fulfill(request.id, "written");
            break;
          }
          case "sign": {
            // The session fixed its algorithm; this proof host signs ES256 only.
            if (request.alg !== "es256") throw new Error(`unsupported signing algorithm: ${request.alg}`);
            stats.signs++;
            const signature = await sign(request);
            session.fulfill(request.id, "signature", signature);
            break;
          }
          default: throw new Error(`unsupported host request: ${request.kind}`);
        }
      }
    }
  } finally { session.close() }
}
