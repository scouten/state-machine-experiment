import { test } from "node:test";
import assert from "node:assert/strict";
import { readAheadBlob, windowBytes } from "../browser/read-ahead.ts";

function source(size = 10_000) {
  const data = Uint8Array.from({ length: size }, (_, i) => i % 251);
  const physical: number[] = [];
  class Slice extends Blob {
    override async arrayBuffer() {
      physical.push(this.size);
      return await super.arrayBuffer();
    }
  }
  class Source extends Blob {
    override slice(start?: number, end?: number, type?: string) {
      return new Slice([super.slice(start, end, type)]);
    }
  }
  return { data, physical, source: new Source([data]) };
}
test("read-ahead answers exact ranges with one bounded window and bypasses large reads", async () => {
  const input = source();
  const { blob, stats } = readAheadBlob(input.source);
  const read = async (start: number, end: number) => new Uint8Array(await blob.slice(start, end).arrayBuffer());
  assert.deepEqual(await read(0, 2), input.data.slice(0, 2));
  assert.deepEqual(await read(20, 24), input.data.slice(20, 24));
  assert.deepEqual(await read(4094, 4098), input.data.slice(4094, 4098));
  assert.deepEqual(await read(5000, 7000), input.data.slice(5000, 7000));
  assert.deepEqual(await read(4100, 4104), input.data.slice(4100, 4104));
  assert.deepEqual(await read(0, 4), input.data.slice(0, 4));
  assert.deepEqual(input.physical, [4096, 4096, 2000, 4096]);
  assert.equal(stats.maxResidentBytes, windowBytes);
  assert.equal(stats.hits, 2);
  assert.equal(stats.fills, 3);
  assert.equal(stats.bypasses, 1);
  assert.deepEqual(stats.logicalReadSizes, [2, 4, 4, 2000, 4, 4]);
});
test("read-ahead preserves Blob slice edge semantics and separate-source ownership", async () => {
  const input = source(100);
  const { blob, stats } = readAheadBlob(input.source);
  for (const [start, end] of [[-4, undefined], [98, 200], [4, 2], [NaN, 2], [-Infinity, 3], [Infinity, undefined]]) {
    assert.deepEqual(await blob.slice(start, end).arrayBuffer(), await input.source.slice(start, end).arrayBuffer());
  }
  assert.ok(stats.maxResidentBytes <= 100);
  assert.deepEqual(await blob.arrayBuffer(), input.data.buffer);
  const other = readAheadBlob(new Blob([Uint8Array.of(9, 8, 7)]));
  assert.deepEqual(new Uint8Array(await other.blob.slice(0, 2).arrayBuffer()), Uint8Array.of(9, 8));
  const first = new Uint8Array(await blob.slice(0, 2).arrayBuffer());
  first[0] = 255;
  assert.deepEqual(new Uint8Array(await blob.slice(0, 2).arrayBuffer()), input.data.slice(0, 2));
});
test("read-ahead propagates failed and short reads, evicts failed fills, and allows explicit retry", async () => {
  for (const mode of ["reject", "short"]) {
    let fail = true;
    class BrokenSlice extends Blob {
      override async arrayBuffer() {
        if (!fail) return await super.arrayBuffer();
        if (mode === "reject") throw new Error("test host failure");
        return new ArrayBuffer(1);
      }
    }
    class BrokenSource extends Blob {
      override slice(start?: number, end?: number) { return new BrokenSlice([super.slice(start, end)]) }
    }
    const { blob } = readAheadBlob(new BrokenSource([new Uint8Array(100)]));
    await assert.rejects(blob.slice(0, 2).arrayBuffer(), /test host failure|Short read-ahead/);
    fail = false;
    assert.equal((await blob.slice(0, 2).arrayBuffer()).byteLength, 2);
    fail = true;
    await assert.rejects(blob.slice(0, 100).arrayBuffer(), /test host failure|Short read-ahead/);
  }
});
test("read-ahead concurrent requests retain their own range and share an overlapping pending fill", async () => {
  const input = source();
  const { blob } = readAheadBlob(input.source);
  const results = await Promise.all([blob.slice(0, 2).arrayBuffer(), blob.slice(20, 24).arrayBuffer(),
    blob.slice(5000, 5004).arrayBuffer()]);
  assert.deepEqual(new Uint8Array(results[0]), input.data.slice(0, 2));
  assert.deepEqual(new Uint8Array(results[1]), input.data.slice(20, 24));
  assert.deepEqual(new Uint8Array(results[2]), input.data.slice(5000, 5004));
  assert.deepEqual(input.physical, [4096, 4096]);
});
test("read-ahead does not cache a synchronous slice failure or poison an unrelated concurrent fill", async () => {
  let fail = true;
  class Source extends Blob {
    override slice(start?: number, end?: number) {
      if (start === 0 && fail) throw new Error("synchronous slice failure");
      return super.slice(start, end);
    }
  }
  const { blob } = readAheadBlob(new Source([new Uint8Array(10_000)]));
  const failed = blob.slice(0, 2).arrayBuffer();
  const good = blob.slice(5000, 5004).arrayBuffer();
  await assert.rejects(failed, /synchronous slice failure/);
  assert.equal((await good).byteLength, 4);
  fail = false;
  assert.equal((await blob.slice(0, 2).arrayBuffer()).byteLength, 2);
});
