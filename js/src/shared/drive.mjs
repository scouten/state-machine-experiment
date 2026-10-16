function range(start, len, length) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(len) ||
      !Number.isSafeInteger(start + len) || start < 0 || len < 0 || start + len > length)
    throw new Error("invalid asset range");
}

export async function read(adapter, asset, settings, now) {
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
            range(start, len, asset.length);
            const bytes = asset.subarray(start, start + len);
            stats.reads++;
            stats.bytes += bytes.length;
            stats.maxReadBytes = Math.max(stats.maxReadBytes, bytes.length);
            session.fulfill(request.id, "bytes", bytes);
            break;
          }
          case "length": session.fulfill(request.id, "length", asset.length); break;
          case "time": session.fulfill(request.id, "time", now); break;
          default: throw new Error(`unsupported host request: ${request.kind}`);
        }
      }));
    }
  } finally { session.close() }
}

export async function build(adapter, asset, definition, certs, sign) {
  const session = adapter.createBuild(definition, certs);
  let output = new Uint8Array(0);
  let length = 0;
  const stats = { reads: 0, bytes: 0, writes: 0, writtenBytes: 0, signs: 0, advances: 0 };
  function stream(name) {
    if (name === "source") return asset;
    if (name === "output") return output.subarray(0, length);
    throw new Error(`unsupported stream: ${name}`);
  }
  try {
    for (;;) {
      stats.advances++;
      const step = session.advance();
      if (step.done) {
        const report = session.finish();
        return { ...report, asset: output.slice(0, length), stats };
      }
      if (!step.requests.length) throw new Error("session stalled without host requests");
      for (const request of step.requests) {
        switch (request.kind) {
          case "read": {
            const bytes = stream(request.stream);
            range(request.start, request.len, bytes.length);
            stats.reads++;
            stats.bytes += request.len;
            session.fulfill(request.id, "bytes", bytes.subarray(request.start, request.start + request.len));
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
