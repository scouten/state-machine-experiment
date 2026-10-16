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
            if (!Number.isSafeInteger(start) || !Number.isSafeInteger(len) ||
                start < 0 || len < 0 || start + len > asset.length) {
              throw new Error("invalid asset range");
            }
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
