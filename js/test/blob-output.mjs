// Test-only storage experiment. No public client option or core request changes.
function range(start, len, length) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(len) ||
      !Number.isSafeInteger(start + len) || start < 0 || len < 0 || start + len > length)
    throw new Error("invalid output range");
}

/** Immutable Blob pieces; missing file extents are logical zero-filled gaps. */
export class BlobOutput {
  length = 0;
  pieces = [];
  stats = { writes: 0, writeBytes: 0, reads: 0, readBytes: 0, maxReadBytes: 0,
    maxReadEnd: 0, explicitReallocationBytes: 0, finalMaterializationBytes: 0, peakPieces: 0,
    patchWrites: 0, patchedBytes: 0 };

  #slice(start, end) {
    const result = [];
    let cursor = 0;
    for (const piece of this.pieces) {
      const next = cursor + piece.length;
      const lo = Math.max(start, cursor);
      const hi = Math.min(end, next);
      if (hi > lo) result.push({ length: hi - lo,
        blob: piece.blob?.slice(lo - cursor, hi - cursor) });
      cursor = next;
    }
    return result;
  }
  write(offset, bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error("invalid output write");
    range(offset, bytes.length, Number.MAX_SAFE_INTEGER);
    const end = offset + bytes.length;
    if (bytes.length && offset < this.length) {
      this.stats.patchWrites++;
      this.stats.patchedBytes += Math.min(bytes.length, this.length - offset);
    }
    const pieces = this.#slice(0, Math.min(offset, this.length));
    if (offset > this.length) pieces.push({ length: offset - this.length });
    if (bytes.length) pieces.push({ length: bytes.length, blob: new Blob([bytes]) });
    pieces.push(...this.#slice(Math.min(end, this.length), this.length));
    this.pieces = pieces;
    this.length = Math.max(this.length, end);
    this.stats.writes++;
    this.stats.writeBytes += bytes.length;
    this.stats.peakPieces = Math.max(this.stats.peakPieces, pieces.length);
  }
  #parts(pieces) {
    const parts = [];
    // Zero holes do not require a single allocation as large as the gap.
    let zeros;
    for (const piece of pieces) {
      if (piece.blob) parts.push(piece.blob);
      else {
        zeros ??= new Uint8Array(65536);
        for (let remaining = piece.length; remaining; remaining -= Math.min(remaining, zeros.length))
          parts.push(zeros.subarray(0, Math.min(remaining, zeros.length)));
      }
    }
    return parts;
  }
  async read(start, len) {
    range(start, len, this.length);
    const bytes = new Uint8Array(await new Blob(this.#parts(this.#slice(start, start + len))).arrayBuffer());
    if (bytes.length !== len) throw new Error("short output read");
    this.stats.reads++;
    this.stats.readBytes += bytes.length;
    this.stats.maxReadBytes = Math.max(this.stats.maxReadBytes, bytes.length);
    this.stats.maxReadEnd = Math.max(this.stats.maxReadEnd, start + bytes.length);
    return bytes;
  }
  finish() { return new Blob(this.#parts(this.pieces), { type: "image/jpeg" }) }
}

/** Instrumented control matching main's geometric array storage and final trim. */
export class ArrayOutput {
  length = 0;
  bytes = new Uint8Array(0);
  stats = { writes: 0, writeBytes: 0, reads: 0, readBytes: 0, maxReadBytes: 0,
    maxReadEnd: 0, explicitReallocationBytes: 0, finalMaterializationBytes: 0, peakCapacity: 0,
    patchWrites: 0, patchedBytes: 0 };
  write(offset, bytes) {
    range(offset, bytes.length, Number.MAX_SAFE_INTEGER);
    const end = offset + bytes.length;
    if (bytes.length && offset < this.length) {
      this.stats.patchWrites++;
      this.stats.patchedBytes += Math.min(bytes.length, this.length - offset);
    }
    if (end > this.bytes.length) {
      const next = new Uint8Array(Math.max(end, this.bytes.length * 2, 4096));
      next.set(this.bytes);
      this.stats.explicitReallocationBytes += this.bytes.length;
      this.bytes = next;
      this.stats.peakCapacity = next.length;
    }
    this.bytes.set(bytes, offset);
    this.stats.writes++;
    this.stats.writeBytes += bytes.length;
    this.length = Math.max(this.length, end);
  }
  async read(start, len) {
    range(start, len, this.length);
    const bytes = this.bytes.subarray(start, start + len);
    this.stats.reads++;
    this.stats.readBytes += bytes.length;
    this.stats.maxReadBytes = Math.max(this.stats.maxReadBytes, bytes.length);
    this.stats.maxReadEnd = Math.max(this.stats.maxReadEnd, start + len);
    return bytes;
  }
  finish() {
    const bytes = this.bytes.slice(0, this.length);
    this.stats.finalMaterializationBytes += bytes.length;
    return bytes;
  }
}

/** Existing main read/write/sign requests, with only output storage substituted. */
export async function buildWithOutput(adapter, asset, definition, certs, sign, output) {
  const session = adapter.createBuild(JSON.stringify(definition), certs);
  const source = { length: asset.length,
    async read(start, len) {
      range(start, len, asset.length);
      return asset.subarray(start, start + len);
    } };
  const stream = (name) => {
    if (name === "source") return source;
    if (name === "output") return output;
    throw new Error(`unsupported stream: ${name}`);
  };
  try {
    for (;;) {
      const step = session.advance();
      if (step.done) return { ...session.finish(), asset: output.finish(), stats: output.stats };
      if (!step.requests.length) throw new Error("session stalled without host requests");
      for (const request of step.requests) {
        switch (request.kind) {
          case "read":
            session.fulfill(request.id, "bytes", await stream(request.stream).read(request.start, request.len));
            break;
          case "length": session.fulfill(request.id, "length", stream(request.stream).length); break;
          case "write":
            if (request.stream !== "output" || !(request.bytes instanceof Uint8Array))
              throw new Error("invalid output write");
            output.write(request.offset, request.bytes);
            session.fulfill(request.id, "written");
            break;
          case "sign":
            if (request.alg !== "es256") throw new Error("unsupported signing algorithm");
            session.fulfill(request.id, "signature", await sign(request));
            break;
          default: throw new Error(`unsupported host request: ${request.kind}`);
        }
      }
    }
  } finally { session.close() }
}
