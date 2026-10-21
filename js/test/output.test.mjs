import assert from "node:assert/strict";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import test from "node:test";
import { BlobOutput, ArrayOutput } from "./blob-output.mjs";
import { outputContract } from "./output-contract.mjs";
import { adapter } from "../src/node/adapter.mjs";

test("Blob pieces preserve overwrites, holes, immutable writes and logical tails", async () => {
  const blob = new BlobOutput();
  const array = new ArrayOutput();
  let seed = 7;
  const random = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed };
  for (const [offset, bytes] of [
    [0, new Uint8Array([1, 2, 3, 4, 5])], [2, new Uint8Array([9])],
    [10, new Uint8Array([7])], [1, new Uint8Array([6, 6, 6, 6, 6])],
    [20, new Uint8Array(0)],
    ...Array.from({ length: 80 }, () =>
      [random() % 500, new Uint8Array(random() % 40).fill(random() % 256)]),
  ]) {
    blob.write(offset, bytes);
    array.write(offset, bytes);
    bytes.fill(255); // Blob constructor must snapshot request payloads.
    assert.equal(blob.length, array.length);
    assert.deepEqual(await blob.read(0, blob.length), await array.read(0, array.length));
    assert.equal(blob.finish().size, array.length);
  }
  for (const [offset, len] of [[-1, 1], [0, blob.length + 1], [0.5, 1],
    [Number.MAX_SAFE_INTEGER, 1], [Infinity, 1], [0, NaN]]) {
    await assert.rejects(blob.read(offset, len), /invalid output range/);
  }
  assert.throws(() => blob.write(-1, new Uint8Array(1)), /invalid output range/);
  assert.throws(() => blob.write(Number.MAX_SAFE_INTEGER, new Uint8Array(1)), /invalid output range/);
  assert.equal((await blob.read(blob.length, 0)).length, 0);
  const stable = blob.finish();
  const before = new Uint8Array(await stable.arrayBuffer());
  blob.write(0, new Uint8Array([99]));
  assert.deepEqual(new Uint8Array(await stable.arrayBuffer()), before, "final Blob is not immutable");
});

test("Blob output bounds holes without a gap-sized byte allocation", async () => {
  const output = new BlobOutput();
  output.write(2 * 1024 * 1024 + 3, new Uint8Array([42]));
  assert.equal(output.pieces.length, 2);
  assert.deepEqual(await output.read(output.length - 3, 3), new Uint8Array([0, 0, 42]));
  assert.equal(output.finish().size, output.length);
});

test("Neon Blob-piece output hashes and patches to Trusted, matching ordinary requests", async () => {
  const folder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder), "utf8"));
  const result = await outputContract(adapter, fixture, await readFile(new URL("test-signer.pk8", folder)));
  await mkdir(new URL("../results/", import.meta.url), { recursive: true });
  await writeFile(new URL("../results/output-node.json", import.meta.url), JSON.stringify(result, null, 2));
  console.log("Node Blob-output measured storage", JSON.stringify(result));
});
