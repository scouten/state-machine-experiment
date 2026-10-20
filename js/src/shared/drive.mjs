/**
 * Shared host loops that drive the synchronous Rust sessions.
 *
 * A session never performs I/O: it parks on `advance()` with a list of
 * requests, and these loops answer them (reads, lengths, writes, signatures)
 * then call `fulfill`. The same code runs in the Node Worker and the browser
 * Worker; only the `adapter` (Neon vs Wasm) differs.
 */

/**
 * Validates a byte range against an asset length: rejects non-integers,
 * negatives, overflow and ranges past the end, so a session's request can
 * never read outside the asset.
 * @throws {Error} `invalid asset range`
 */
export function range(start, len, length) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(len) ||
      !Number.isSafeInteger(start + len) || start < 0 || len < 0 || start + len > length)
    throw new Error("invalid asset range");
}

export function source(asset) {
  const length = asset instanceof Blob ? asset.size : asset.length;
  return {
    length,
    async close() {},
    async read(start, len) {
      range(start, len, length);
      const bytes = asset instanceof Blob
        ? new Uint8Array(await asset.slice(start, start + len).arrayBuffer())
        : asset.subarray(start, start + len);
      if (bytes.length !== len) throw new Error("short asset read");
      return bytes;
    },
  };
}

/**
 * Runs a read/validation session to completion. Requests in one step are
 * independent, so they are answered concurrently.
 * @param {{create(settings?: string): object}} adapter Session factory (Neon or Wasm).
 * @param {Uint8Array|Blob|object} input Asset bytes, Blob or host source
 * @param {string|undefined} settings JSON reader settings.
 * @param {number} now Unix seconds supplied as the session's clock.
 * @returns {Promise<{report: object|null, stats: object}>} Parsed report
 *   (`null` when the asset has no manifest store) and request counters.
 */
export async function read(adapter, input, settings, now) {
  const session = adapter.create(settings);
  const stats = { reads: 0, bytes: 0, maxReadBytes: 0, advances: 0 };
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
      await Promise.all(step.requests.map(async (request) => {
        switch (request.kind) {
          case "read": {
            const { start, len } = request;
            const bytes = await input.read(start, len);
            stats.reads++;
            stats.bytes += bytes.length;
            stats.maxReadBytes = Math.max(stats.maxReadBytes, bytes.length);
            session.fulfill(request.id, "bytes", bytes);
            break;
          }
          case "length": session.fulfill(request.id, "length", input.length); break;
          case "time": session.fulfill(request.id, "time", now); break;
          default: throw new Error(`unsupported host request: ${request.kind}`);
        }
      }));
    }
  } finally { session.close() }
}

export function memoryOutput() {
  let output = new Uint8Array(0);
  /** Logical output length; `output` may be larger (geometric growth). */
  let length = 0;
  return {
    get length() { return length },
    read: (start, len) => source(output.subarray(0, length)).read(start, len),
    async write(offset, bytes) {
      range(offset, bytes.length, Number.MAX_SAFE_INTEGER);
      const end = offset + bytes.length;
      if (end > output.length) {
        const next = new Uint8Array(Math.max(end, output.length * 2, 4096));
        next.set(output);
        output = next;
      }
      output.set(bytes, offset);
      length = Math.max(length, end);
    },
    async finish() { return { asset: output.slice(0, length) } },
    async close() {},
  };
}

export const algorithms = new Set(["es256", "es384", "es512", "ps256", "ps384", "ps512", "ed25519"]);
const rawSignatureLength = { es256: 64, es384: 96, es512: 132, ed25519: 64 };

// RSA-PSS signature length depends on the key, so only fixed-width algorithms are checked.
export function checkSignature(alg, value) {
  const expected = rawSignatureLength[alg];
  if (!(value instanceof Uint8Array) || (expected !== undefined && value.length !== expected))
    throw new TypeError(expected === undefined ? `${alg} signer must return signature bytes`
      : `${alg} signer must return ${expected} raw signature bytes`);
  if (value.length === 0) throw new TypeError(`${alg} signer returned no bytes`);
}

const timestampLimit = 1024 * 1024;

// Worker-side default for a timestamp request; the host only ever POSTs.
export async function postTimestamp({ url, request }) {
  const target = new URL(url);
  if (target.protocol !== "http:" && target.protocol !== "https:")
    throw new Error("timestamp authority URL must be http or https");
  const response = await fetch(target, { method: "POST", redirect: "error",
    headers: { "content-type": "application/timestamp-query" }, body: request });
  if (!response.ok) throw new Error(`the timestamp authority answered ${response.status}`);
  const body = new Uint8Array(await response.arrayBuffer());
  if (body.length > timestampLimit) throw new Error("the timestamp response is implausibly large");
  return body;
}

/**
 * Runs a build-and-sign session to completion. Requests are answered
 * sequentially: the builder's two passes depend on earlier writes. Source and
 * output are addressed by stream name; the output defaults to memory.
 * @param {{createBuild(definition: string, certs: Uint8Array[], alg: string): object}} adapter
 * @param {Uint8Array|Blob|object} input Asset to sign.
 * @param {string} definition JSON manifest definition.
 * @param {Uint8Array[]} certs DER certificate chain, leaf first.
 * @param {(request: {id: number, alg: string, data: Uint8Array}) => Promise<Uint8Array>} sign
 *   Produces the raw signature over `request.data` for `alg`.
 * @param {object} [output] Output sink; defaults to {@link memoryOutput}.
 * @param {string} [alg] Signing algorithm; one of {@link algorithms}.
 * @param {(request: {url: string, request: Uint8Array}) => Promise<Uint8Array>} [timestamp]
 *   Answers a timestamp request; defaults to {@link postTimestamp}.
 * @returns {Promise<object>} Builder report plus the signed `asset` and `stats`.
 */
export async function build(adapter, input, definition, certs, sign, output = memoryOutput(),
  alg = "es256", timestamp = postTimestamp) {
  const session = adapter.createBuild(definition, certs, alg);
  const stats = { reads: 0, bytes: 0, maxSourceReadBytes: 0, writes: 0, writtenBytes: 0, signs: 0, advances: 0 };
  function stream(name) {
    if (name === "source") return input;
    if (name === "output") return output;
    throw new Error(`unsupported stream: ${name}`);
  }
  try {
    for (;;) {
      stats.advances++;
      const step = session.advance();
      if (step.done) {
        const report = session.finish();
        return { ...report, ...await output.finish(), stats };
      }
      if (!step.requests.length) throw new Error("session stalled without host requests");
      for (const request of step.requests) {
        switch (request.kind) {
          case "read": {
            const bytes = await stream(request.stream).read(request.start, request.len);
            stats.reads++;
            stats.bytes += request.len;
            if (request.stream === "source")
              stats.maxSourceReadBytes = Math.max(stats.maxSourceReadBytes, request.len);
            session.fulfill(request.id, "bytes", bytes);
            break;
          }
          case "length": session.fulfill(request.id, "length", stream(request.stream).length); break;
          case "write": {
            if (request.stream !== "output" || !(request.bytes instanceof Uint8Array))
              throw new Error("invalid output write");
            await output.write(request.offset, request.bytes);
            stats.writes++;
            stats.writtenBytes += request.bytes.length;
            session.fulfill(request.id, "written");
            break;
          }
          case "sign": {
            if (request.alg !== alg) throw new Error(`session asked for ${request.alg}, signer is ${alg}`);
            stats.signs++;
            const signature = await sign(request);
            session.fulfill(request.id, "signature", signature);
            break;
          }
          case "timestamp": {
            stats.timestamps = (stats.timestamps ?? 0) + 1;
            session.fulfill(request.id, "timestampResponse", await timestamp(request));
            break;
          }
          default: throw new Error(`unsupported host request: ${request.kind}`);
        }
      }
    }
  } finally { session.close() }
}
