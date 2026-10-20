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
 * @param {string} [format] Asset type (MIME type or extension).
 * @param {{allowPrivateHosts?: boolean}} [ocspPolicy] See {@link postOcsp}. A
 *   refused or failed OCSP fetch is reported to the engine, which fails open.
 * @returns {Promise<{report: object|null, stats: object}>} Parsed report
 *   (`null` when the asset has no manifest store) and request counters.
 */
export async function read(adapter, input, settings, now, format = "image/jpeg", ocspPolicy = {}) {
  const session = adapter.create(settings, format);
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
          case "ocsp": {
            stats.ocsp = (stats.ocsp ?? 0) + 1;
            try { session.fulfill(request.id, "ocsp", await postOcsp(request, ocspPolicy)) }
            catch (error) { session.fulfill(request.id, "failed", String(error?.message ?? error)) }
            break;
          }
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

const timestampDeadlineMs = 30_000;

// Worker-side default for a timestamp request; the host only ever POSTs. One
// deadline covers connecting and reading the body, and the body is cancelled as
// soon as it exceeds the size limit, so a faulty authority can neither stall
// the Worker's queue nor exhaust its memory.
export async function postTimestamp({ url, request }, deadlineMs = timestampDeadlineMs) {
  const target = new URL(url);
  if (target.protocol !== "http:" && target.protocol !== "https:")
    throw new Error("timestamp authority URL must be http or https");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), deadlineMs);
  try {
    const response = await fetch(target, { method: "POST", redirect: "error", signal: controller.signal,
      headers: { "content-type": "application/timestamp-query" }, body: request });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`the timestamp authority answered ${response.status}`);
    }
    const chunks = [];
    let length = 0;
    for await (const chunk of response.body ?? []) {
      length += chunk.length;
      if (length > timestampLimit) {
        controller.abort();
        throw new Error("the timestamp response is implausibly large");
      }
      chunks.push(chunk);
    }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length }
    return body;
  } catch (error) {
    if (controller.signal.aborted && !/implausibly/.test(error.message))
      throw new Error(`the timestamp authority did not answer within ${deadlineMs} ms`);
    throw error;
  } finally { clearTimeout(timer) }
}

/**
 * Whether `hostname` (as `URL.hostname` spells it) is a literal loopback,
 * private, link-local or otherwise non-public address, or `localhost`.
 * Names that merely resolve to such addresses are not detected.
 * @param {string} hostname
 */
export function isNonPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (host.includes(":")) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
    if (mapped) return isNonPublicHost(mapped[1]);
    // `URL` normalizes a mapped IPv4 address to hex groups (::ffff:7f00:1).
    const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (hex) {
      const high = parseInt(hex[1], 16), low = parseInt(hex[2], 16);
      return isNonPublicHost(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
    }
    return host === "::" || host === "::1" || /^f[cd]/.test(host) || /^fe[89ab]/.test(host);
  }
  return false;
}

/**
 * Default OCSP transport: POSTs the Rust-built `OCSPRequest` and returns the
 * response body. The responder URL comes from the signer's certificate, so it
 * is untrusted input: only http(s), no redirects, a 1 MiB cap, and non-public
 * literal hosts are refused unless the caller opts in with `allowPrivateHosts`.
 * @param {{url: string, requestDer: Uint8Array}} request
 * @param {{allowPrivateHosts?: boolean}} [policy]
 * @returns {Promise<Uint8Array>}
 */
export async function postOcsp({ url, requestDer }, { allowPrivateHosts = false } = {}) {
  const target = new URL(url);
  if (target.protocol !== "http:" && target.protocol !== "https:")
    throw new Error("OCSP responder URL must be http or https");
  if (!allowPrivateHosts && isNonPublicHost(target.hostname))
    throw new Error("OCSP responder host is not public");
  const response = await fetch(target, { method: "POST", redirect: "error",
    headers: { "content-type": "application/ocsp-request" }, body: requestDer });
  if (!response.ok) throw new Error(`the OCSP responder answered ${response.status}`);
  const body = new Uint8Array(await response.arrayBuffer());
  if (body.length > timestampLimit) throw new Error("the OCSP response is implausibly large");
  return body;
}

/**
 * Position of a CAWG identity assertion label among the declared identities:
 * `cawg.identity` is 0, `cawg.identity__N` is N.
 * @param {string} label
 */
export function identityIndex(label) {
  const match = /^cawg\.identity(?:__(\d+))?$/.exec(label);
  if (!match) throw new Error(`unexpected identity label ${label}`);
  return match[1] === undefined ? 0 : Number(match[1]);
}

/**
 * Runs a build-and-sign session to completion.
 * Requests are answered sequentially: the builder's two passes depend on
 * earlier writes. Source and output are addressed by stream name.
 * @param {{createBuild(definition: string, certs: Uint8Array[], alg: Algorithm): object}} adapter
 * @param {Source} input Asset to sign.
 * @param {string} definition JSON manifest definition.
 * @param {Uint8Array[]} certs DER certificate chain, leaf first.
 * @param {(request: {id: number, alg: Algorithm, data: Uint8Array}) => Promise<Uint8Array>} sign
 *   Produces a raw signature over `request.data`.
 * @param {Output} [output] Destination; defaults to memory.
 * @param {Algorithm} [alg] Must match what the session asks for.
 * @param {Function} [timestamp] Answers timestamp requests.
 * @param {{format?: string, identities?: {alg: Algorithm, certs: Uint8Array[], roles?: string[], referencedAssertions?: string[]}[]}} [extra]
 *   Asset type (MIME type or extension; default JPEG) and CAWG identities to add.
 * @param {(request: {url: string, request: Uint8Array}) => Promise<Uint8Array>} [timestamp]
 *   Answers timestamp requests; a failure fails the build (never silently unstamped).
 * @returns {Promise<object>} Builder report plus `output.finish()` fields and `stats`.
 */
export async function build(adapter, input, definition, certs, sign, output = memoryOutput(),
  alg = "es256", timestamp = postTimestamp, { format = "image/jpeg", identities = [] } = {}) {
  const session = adapter.createBuild(definition, certs, alg, format, identities);
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
            // The session fixed its algorithms at creation; a mismatch means a wrong signer.
            const expected = request.identity == null ? alg : identities[identityIndex(request.identity)]?.alg;
            if (request.alg !== expected) throw new Error(`session asked for ${request.alg}, signer is ${expected}`);
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
