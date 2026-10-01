import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import test from "node:test";

import { Reader } from "../index.mjs";

const PATH = new URL("../../contentauth-c2pa-reader/tests/fixtures/C.jpg", import.meta.url)
  .pathname;
const BYTES = readFileSync(PATH);
// Inside every certificate's validity window, and not the wall clock, so a
// pass proves the *host's* clock was the one the engine used.
const now = () => 1_800_000_000_000;

/** An asset whose reads genuinely take time, and which records concurrency. */
function slowAsset(delayMs = 5) {
  const stats = { reads: 0, inFlight: 0, maxInFlight: 0 };
  return {
    stats,
    size: BYTES.length,
    async read(start, len) {
      stats.reads++;
      stats.maxInFlight = Math.max(stats.maxInFlight, ++stats.inFlight);
      await sleep(delayMs);
      stats.inFlight--;
      return BYTES.subarray(start, start + len);
    },
  };
}

test("reads a signed JPEG from a path, a buffer, and an async source alike", async () => {
  const fromPath = await Reader.fromAsset({ path: PATH }, null, { now });
  const fromBuffer = await Reader.fromAsset({ buffer: BYTES, mimeType: "image/jpeg" }, null, { now });
  const fromSource = await Reader.fromAsset(slowAsset(), null, { now });

  assert.ok(fromPath.activeLabel());
  assert.equal(fromPath.json().validation_state, "Valid");
  assert.deepEqual(fromBuffer.json(), fromPath.json());
  assert.deepEqual(fromSource.json(), fromPath.json());
  assert.equal(fromPath.getActive().label, fromPath.activeLabel());
  assert.equal(fromPath.isEmbedded(), true);
  assert.equal(fromPath.remoteUrl(), "");
});

test("the format is sniffed from the bytes when no mime type or extension is given", async () => {
  const reader = await Reader.fromAsset({ buffer: BYTES }, null, { now });
  assert.ok(reader.activeLabel());
});

test("an asset with no manifest store resolves to null, as in c2pa-node", async () => {
  const bare = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
  assert.equal(await Reader.fromAsset({ buffer: bare, mimeType: "image/jpeg" }), null);
});

test("errors carry c2pa-rs's Debug string as their name", async () => {
  await assert.rejects(
    Reader.fromAsset({ buffer: BYTES, mimeType: "image/png" }),
    { name: "C2pa(UnsupportedType)" },
  );
  await assert.rejects(
    Reader.fromAsset({ buffer: BYTES, mimeType: "image/jpeg" }, "{not json"),
    (err) => err.name.startsWith("C2pa(BadParam("),
  );
  await assert.rejects(Reader.fromAsset({ path: "/no/such/file.jpg" }), { code: "ENOENT" });
});

test("the host decides how many requests run at once", async () => {
  const unlimited = slowAsset();
  await Reader.fromAsset(unlimited, null, { now });
  assert.ok(unlimited.stats.maxInFlight > 1, JSON.stringify(unlimited.stats));

  const serial = slowAsset();
  await Reader.fromAsset(serial, null, { now, concurrency: 1 });
  assert.equal(serial.stats.maxInFlight, 1);
  assert.equal(serial.stats.reads, unlimited.stats.reads);

  const two = slowAsset();
  await Reader.fromAsset(two, null, { now, concurrency: 2 });
  assert.equal(two.stats.maxInFlight, 2);
});

test("the JS thread is never blocked: timers fire throughout a slow read", async () => {
  const asset = slowAsset(20);
  let ticks = 0;
  const timer = setInterval(() => ticks++, 1);
  const started = performance.now();
  await Reader.fromAsset(asset, null, { now, concurrency: 1 });
  clearInterval(timer);

  const elapsed = performance.now() - started;
  assert.ok(elapsed >= 20 * asset.stats.reads * 0.9, `${elapsed}ms`);
  assert.ok(ticks > asset.stats.reads, `${ticks} ticks over ${asset.stats.reads} reads`);
});

test("many reads interleave on the one thread", async () => {
  const assets = Array.from({ length: 8 }, () => slowAsset(10));
  const started = performance.now();
  const readers = await Promise.all(assets.map((a) => Reader.fromAsset(a, null, { now })));
  const elapsed = performance.now() - started;

  for (const reader of readers) assert.equal(reader.json().validation_state, "Valid");
  const serialMs = assets.reduce((sum, a) => sum + a.stats.reads * 10, 0);
  assert.ok(elapsed < serialMs / 2, `${elapsed}ms vs ${serialMs}ms if serial`);
});

test("a source that fails mid-read fails the read, not the process", async () => {
  const asset = { ...slowAsset(), read: async () => { throw new Error("disk on fire"); } };
  await assert.rejects(Reader.fromAsset(asset, null, { now }));
});
