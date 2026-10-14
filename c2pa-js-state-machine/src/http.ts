export interface HttpHostOptions {
  /** Exact origins authorized by the caller, not by asset metadata. */
  allowedOrigins: readonly string[];
  /** Maximum decoded response bytes. */
  maxBytes: number;
  /** Deadline covers fetch and the complete streamed response. */
  timeoutMs: number;
  signal?: AbortSignal;
}

export function boundedHttpHost(options: HttpHostOptions, label: string, allowHttp = false):
  (url: string, request?: Uint8Array) => Promise<Uint8Array> {
  if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes <= 0 ||
      !Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0 ||
      options.timeoutMs > 2_147_483_647)
    throw new Error(`${label} limits must be positive safe integers`);
  const origins = new Set(options.allowedOrigins.map((origin) => {
    const url = new URL(origin);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.origin !== origin || (url.protocol !== "https:" &&
        !(url.protocol === "http:" && (allowHttp || loopback))))
      throw new Error(`${label} allowlist must contain exact permitted origins`);
    return origin;
  }));
  if (origins.size === 0) throw new Error(`${label} origin allowlist must not be empty`);
  const { maxBytes, timeoutMs, signal } = options;
  return async (value, request) => {
    const url = new URL(value);
    if (!origins.has(url.origin) || url.username || url.password || url.hash)
      throw new Error(`${label} URL denied by host policy`);
    const controller = new AbortController();
    const abort = () => controller.abort(signal?.reason);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const timer = setTimeout(() => controller.abort(new Error(`${label} deadline exceeded`)), timeoutMs);
    try {
      controller.signal.throwIfAborted();
      const response = await fetch(url, {
        signal: controller.signal, redirect: "error", credentials: "omit",
        referrerPolicy: "no-referrer", cache: "no-store",
        ...(request === undefined ? {} : {
          method: "POST", body: new Uint8Array(request),
          headers: { "Content-Type": "application/ocsp-request", Accept: "application/ocsp-response" },
        }),
      });
      if (!response.ok) throw new Error(`${label} HTTP status ${response.status}`);
      if (!response.body) throw new Error(`${label} response has no body`);
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      try {
        const declared = response.headers.get("content-length");
        if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
          await reader.cancel();
          throw new Error(`${label} response exceeds byte limit`);
        }
        for (;;) {
          controller.signal.throwIfAborted();
          const { done, value: chunk } = await reader.read();
          if (done) break;
          if (chunk.byteLength > maxBytes - length) {
            await reader.cancel();
            throw new Error(`${label} response exceeds byte limit`);
          }
          chunks.push(chunk);
          length += chunk.byteLength;
        }
        controller.signal.throwIfAborted();
      } catch (cause) {
        controller.abort(cause);
        throw cause;
      } finally { reader.releaseLock() }
      if (length === 0) throw new Error(`${label} response is empty`);
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
      return bytes;
    } catch (cause) {
      controller.signal.throwIfAborted();
      throw cause;
    } finally {
      controller.abort();
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  };
}
