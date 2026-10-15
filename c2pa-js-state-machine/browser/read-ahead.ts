export const windowBytes = 4096;
export const smallReadBytes = 64;
export interface ReadAheadStats {
  windowBytes: number;
  logicalReadSizes: number[];
  hits: number;
  fills: number;
  bypasses: number;
  maxResidentBytes: number;
}
export function readAheadBlob(source: Blob): { blob: Blob; stats: ReadAheadStats } {
  const stats: ReadAheadStats = {
    windowBytes, logicalReadSizes: [], hits: 0, fills: 0, bypasses: 0, maxResidentBytes: 0,
  };
  let cache: { start: number; end: number; data: Promise<ArrayBuffer> } | undefined;
  const normalize = (value: number | undefined, fallback: number) => {
    const integer = value === undefined ? fallback : !Number.isFinite(value) ? 0 : Math.trunc(value);
    return integer < 0 ? Math.max(source.size + integer, 0) : Math.min(integer, source.size);
  };
  async function read(start: number, end: number): Promise<ArrayBuffer> {
    const length = end - start;
    stats.logicalReadSizes.push(length);
    if (length === 0) return new ArrayBuffer(0);
    if (length > smallReadBytes) {
      stats.bypasses++;
      const data = await source.slice(start, end).arrayBuffer();
      if (data.byteLength !== length) throw new Error("Short read-ahead bypass read");
      return data;
    }
    if (cache && start >= cache.start && end <= cache.end) stats.hits++;
    else {
      const fillEnd = Math.min(source.size, start + windowBytes);
      const pending = (async () => {
        const data = await source.slice(start, fillEnd).arrayBuffer();
        if (data.byteLength !== fillEnd - start) throw new Error("Short read-ahead window read");
        stats.maxResidentBytes = Math.max(stats.maxResidentBytes, data.byteLength);
        return data;
      })();
      const entry = { start, end: fillEnd, data: pending };
      cache = entry;
      stats.fills++;
      entry.data = pending.catch((cause: unknown) => {
        if (cache === entry) cache = undefined;
        throw cause;
      });
    }
    const active = cache;
    if (!active) throw new Error("Read-ahead window lost");
    const data = await active.data;
    return data.slice(start - active.start, end - active.start);
  }
  class Slice extends Blob {
    constructor(private start: number, private end: number, type?: string) {
      super([Blob.prototype.slice.call(source, start, end)], { type });
    }
    override async arrayBuffer(): Promise<ArrayBuffer> { return await read(this.start, this.end) }
  }
  class Source extends Blob {
    override slice(start?: number, end?: number, type?: string): Blob {
      const from = normalize(start, 0);
      return new Slice(from, Math.max(from, normalize(end, source.size)), type);
    }
    override async arrayBuffer(): Promise<ArrayBuffer> { return await read(0, source.size) }
  }
  return { blob: new Source([source], { type: source.type }), stats };
}
