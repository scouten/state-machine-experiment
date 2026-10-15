import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Reader } from "../index.mjs";

const fixture = (path) => new URL(`../../${path}`, import.meta.url);
const resources = (name) => fixture(`c2pa-js-state-machine/browser/fixtures/${name}`);
const now = () => 1_800_000_000_000;
const settings = { verify: { ocsp_fetch: false } };
const svg = await readFile(resources("generator-icon.svg"));
const data = await readFile(resources("ingredient-data.json"));

async function read(name) {
  return Reader.fromAsset({ buffer: await readFile(resources(name)) }, settings, { now });
}

// Adapted from pinned c2pa-node Reader.spec.ts's "should write to a file",
// using the repository's C.jpg fixture instead of upstream's CA.jpg.
test("claim resourceToAsset preserves legacy buffer/file result shapes after the source is gone", async () => {
  const directory = await mkdtemp(join(tmpdir(), "c2pa-node-resource-"));
  try {
    const source = join(directory, "source.jpg");
    await writeFile(source, await readFile(fixture("contentauth-c2pa-reader/tests/fixtures/C.jpg")));
    const reader = await Reader.fromAsset({ path: source }, settings, { now });
    await rm(source);
    const uri = reader.getActive().thumbnail.identifier;
    const destination = { buffer: Buffer.from("not an output prefix") };
    const result = await reader.resourceToAsset(uri, destination);
    assert.deepEqual(Object.keys(result).sort(), ["buffer", "bytes_written"]);
    assert.ok(Buffer.isBuffer(result.buffer));
    assert.equal(result.bytes_written, 28486);
    assert.equal(result.buffer.length, result.bytes_written);
    assert.equal(destination.buffer.toString(), "not an output prefix");

    const output = join(directory, "thumbnail.jpg");
    await writeFile(output, Buffer.alloc(result.bytes_written + 100, 0x7f));
    const written = await reader.resourceToAsset(uri, { path: output });
    assert.deepEqual(written, { buffer: Buffer.alloc(0), bytes_written: result.bytes_written });
    assert.deepEqual(await readFile(output), result.buffer);
    const expected = Buffer.from(result.buffer);
    result.buffer.fill(0);
    assert.deepEqual((await reader.resourceToAsset(uri, { buffer: null })).buffer, expected);
    assert.deepEqual(Object.keys(reader), []);
    assert.equal(JSON.stringify(reader), "{}");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("generator icons and positional ingredient thumbnails return exact independent resource bytes", async () => {
  const iconReader = await read("generator-icons-v2.jpg");
  const icon = iconReader.getActive().claim_generator_info[0].icon;
  assert.deepEqual((await iconReader.resourceToAsset(icon.identifier, { buffer: null })).buffer, svg);

  const reader = await read("ingredient-thumbnails-v2.jpg");
  const thumbnails = reader.getActive().ingredients.map((ingredient) => ingredient.thumbnail);
  assert.notEqual(thumbnails[0].identifier, thumbnails[1].identifier);
  const first = await reader.resourceToAsset(thumbnails[0].identifier, { buffer: null });
  const second = await reader.resourceToAsset(thumbnails[1].identifier, { buffer: null });
  assert.deepEqual(first.buffer, svg);
  assert.deepEqual(second.buffer, svg);
  assert.notStrictEqual(first.buffer, second.buffer);
  first.buffer.fill(0);
  assert.deepEqual(second.buffer, svg);
  assert.deepEqual((await reader.resourceToAsset(thumbnails[0].identifier, { buffer: null })).buffer, svg);
});

test("ingredient data and thumbnails coexist without source reads or network access", async () => {
  const asset = await readFile(resources("ingredient-data-v2.jpg"));
  let reads = 0;
  let closed = false;
  const reader = await Reader.fromAsset({
    size: asset.length,
    async read(start, len) {
      assert.equal(closed, false, "resource extraction must not revisit the source");
      reads++;
      return asset.subarray(start, start + len);
    },
  }, settings, { now, fetch: () => assert.fail("offline resources must not fetch") });
  closed = true;
  const count = reads;
  const ingredients = reader.getActive().ingredients;
  const before = reader.json();
  const results = await Promise.all(ingredients.map((ingredient) =>
    reader.resourceToAsset(ingredient.data.identifier, { buffer: null })));
  assert.deepEqual(results[0], { buffer: data, bytes_written: data.length });
  assert.deepEqual(results[1], { buffer: data, bytes_written: data.length });
  assert.notStrictEqual(results[0].buffer, results[1].buffer);
  assert.deepEqual((await reader.resourceToAsset(ingredients[0].thumbnail.identifier, { buffer: null })).buffer, svg);
  results[0].buffer.fill(0);
  assert.deepEqual(results[1].buffer, data);
  assert.deepEqual((await reader.resourceToAsset(ingredients[0].data.identifier, { buffer: null })).buffer, data);
  assert.equal(reads, count);
  assert.deepEqual(reader.json(), before);
});

test("strict URI and destination failures leave outputs untouched and allow retries", async () => {
  const reader = await read("ingredient-data-v2.jpg");
  const uri = reader.getActive().ingredients[0].data.identifier;
  const directory = await mkdtemp(join(tmpdir(), "c2pa-node-resource-errors-"));
  try {
    const output = join(directory, "untouched.json");
    await writeFile(output, "keep me");
    for (const bad of [
      "", "c2pa.embedded-data", "self#jumbf=c2pa.assertions/c2pa.embedded-data",
      "https://example.invalid/data", uri.replace("/c2pa/", "/other/"),
      uri.replace("/c2pa.assertions/", "/c2pa.databoxes/"),
      `${uri}__999`, `${uri}/nested`,
    ]) {
      await assert.rejects(reader.resourceToAsset(bad, { path: output }),
        (error) => error.name.startsWith("C2pa(ResourceNotFound("));
      assert.equal(await readFile(output, "utf8"), "keep me");
    }
    for (const bad of [null, {}, { buffer: "bad" }, { path: "" }, { path: 42 },
      { buffer: null, path: output }, { buffer: null, path: 42 }, { buffer: "bad", path: output }]) {
      await assert.rejects(reader.resourceToAsset(uri, bad), TypeError);
    }
    await assert.rejects(reader.resourceToAsset(42, { buffer: null }), TypeError);
    await assert.rejects(reader.resourceToAsset(uri, { path: join(directory, "missing", "out") }), { code: "ENOENT" });
    assert.deepEqual((await reader.resourceToAsset(uri, { buffer: null })).buffer, data);
    assert.equal(await readFile(output, "utf8"), "keep me");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("data extraction preserves live tamper failures and isolates unrelated resources", async () => {
  const asset = await readFile(resources("ingredient-data-v2.jpg"));
  const marker = Buffer.from("M3_INGREDIENT_DATA_EXACT_BYTES");
  const offset = asset.indexOf(marker);
  assert.ok(offset >= 0);
  asset[offset] ^= 1;
  const reader = await Reader.fromAsset({ buffer: asset }, settings, { now });
  const before = reader.json();
  assert.equal(before.validation_state, "Invalid");
  assert.ok(before.validation_status.some((status) => status.code === "assertion.hashedURI.mismatch"));
  const ingredients = reader.getActive().ingredients;
  const changed = Buffer.from(data);
  changed[changed.indexOf(marker)] ^= 1;
  assert.deepEqual((await reader.resourceToAsset(ingredients[0].data.identifier, { buffer: null })).buffer, changed);
  assert.deepEqual((await reader.resourceToAsset(ingredients[1].data.identifier, { buffer: null })).buffer, data);
  assert.deepEqual((await reader.resourceToAsset(ingredients[0].thumbnail.identifier, { buffer: null })).buffer, svg);
  assert.deepEqual(reader.json(), before);
});

test("unsupported databox reporting still rejects and later resource reads recover", async () => {
  for (const asset of ["generator-icons-v1.jpg", "ingredient-thumbnails-v1.jpg", "ingredient-data-v1.jpg"]) {
    await assert.rejects(read(asset), /same-manifest embedded assertion/);
  }
  const reader = await read("ingredient-data-v2.jpg");
  assert.deepEqual((await reader.resourceToAsset(reader.getActive().ingredients[0].data.identifier,
    { buffer: null })).buffer, data);
});
