import assert from "node:assert/strict";
import test from "node:test";
import { readFile, open, unlink } from "node:fs/promises";
import { openSource, snapshotAsset } from "../src/shared/source.mjs";
import { openNodeSource, snapshotNodeAsset } from "../src/node/source.mjs";
import { read } from "../src/shared/drive.mjs";
import { serve, protocol } from "../src/shared/service.mjs";
import { createClient } from "../src/node/client.mjs";
import { rangeContract } from "./range-contract.mjs";

test("Blob only materializes exact validated slices; byte snapshots stay eager", async () => {
  const ranges = [];
  class ObservedBlob extends Blob {
    arrayBuffer() { throw new Error("whole Blob conversion") }
    slice(start, end) { ranges.push([start, end]); return super.slice(start, end) }
  }
  const blob = new ObservedBlob([new Uint8Array([1, 2, 3, 4])]);
  assert.equal(snapshotAsset(blob), blob);
  const source = openSource(blob);
  assert.deepEqual(await source.read(1, 2), new Uint8Array([2, 3]));
  assert.equal((await source.read(4, 0)).length, 0);
  for (const [start, len] of [[-1, 1], [0, 5], [0.5, 1], [Infinity, 0],
    [Number.MAX_SAFE_INTEGER, 1], [0, NaN]]) {
    await assert.rejects(source.read(start, len), /invalid asset range/);
  }
  assert.deepEqual(ranges, [[1, 3], [4, 4]]);
  const bytes = new Uint8Array([9]);
  bytes.path = "must-not-override-byte-semantics";
  const snapshot = snapshotAsset(bytes);
  const nodeSnapshot = snapshotNodeAsset(bytes);
  bytes[0] = 0;
  assert.equal(snapshot[0], 9);
  assert.equal(nodeSnapshot[0], 9);
  assert.throws(() => snapshotAsset({ size: 4 }), TypeError);
});

test("read failure waits for other in-flight reads before closing session", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve });
  let closed = false;
  const fulfilled = [];
  const result = read({ create: () => ({
    advance: () => ({ requests: [
      { id: 1, kind: "read", start: 0, len: 1 },
      { id: 2, kind: "read", start: 1, len: 1 },
    ] }),
    fulfill(id) { assert.equal(closed, false); fulfilled.push(id) },
    close() { closed = true },
  }) }, null, undefined, 0, {
    length: 2,
    async read(start) {
      if (!start) throw new Error("range read failed");
      await gate;
      return new Uint8Array(1);
    },
  });
  const rejected = assert.rejects(result, /range read failed/);
  await Promise.resolve();
  assert.equal(closed, false);
  release();
  await rejected;
  assert.equal(closed, true);
  assert.deepEqual(fulfilled, [2]);
});

test("service closes failed sources without poisoning FIFO or masking the error", async () => {
  let receive;
  let resolve;
  const done = new Promise((finish) => { resolve = finish });
  const replies = [];
  const closed = [];
  let created = 0;
  serve({
    onMessage(callback) { receive = callback },
    post(message) { replies.push(message); if (message.id === 2) resolve() },
  }, {
    create() {
      if (!created++) throw new TypeError("invalid settings");
      return { advance: () => ({ done: true }), finish: () => null, close() {} };
    },
  }, async (asset) => ({
    length: 0,
    async close() {
      closed.push(asset);
      if (asset === 1) throw new Error("cleanup failure");
    },
  }));
  receive({ protocol, id: 1, method: "read", asset: 1 });
  receive({ protocol, id: 2, method: "read", asset: 2 });
  await done;
  assert.deepEqual(closed, [1, 2]);
  assert.deepEqual(replies[1].error, { name: "TypeError", message: "invalid settings" });
  assert.equal(replies[2].ok, true);
});

test("Node file source uses positioned reads, detects truncation, and closes", async () => {
  const path = new URL("../generated/source-unit.bin", import.meta.url);
  const writer = await open(path, "w+");
  let source;
  try {
    await writer.write(new Uint8Array([0, 1, 2, 3]));
    source = await openNodeSource({ path: path.pathname });
    assert.deepEqual(await source.read(2, 2), new Uint8Array([2, 3]));
    await assert.rejects(source.read(3, 2), /invalid asset range/);
    await writer.truncate(1);
    await assert.rejects(source.read(0, 4), /short asset read/);
  } finally { await source?.close(); await writer.close(); await unlink(path) }
  await assert.rejects(source.read(0, 1), /closed/);
});

test("Node file-backed read/sign produces Trusted output with bounded actual reads", async () => {
  const folder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder), "utf8"));
  const path = new URL("range-source.jpg", folder);
  const file = await open(path, "w");
  try {
    await file.write(new Uint8Array([255, 216, 255, 217]));
    await file.truncate(fixture.signing.files.large.sourceBytes);
  } finally { await file.close() }
  try {
    const result = await rangeContract(createClient,
      { path: new URL("large.jpg", folder).pathname }, { path: path.pathname },
      fixture, await readFile(new URL("test-signer.pk8", folder)));
    console.log("Node actual file-source I/O", JSON.stringify(result));
  } finally { await unlink(path) }
  const client = createClient();
  try {
    await assert.rejects(client.read({ path: path.pathname }), /ENOENT/);
    assert.equal((await client.read(new Uint8Array([255, 216, 255, 217]))).report, null);
  } finally { await client.dispose() }
});
