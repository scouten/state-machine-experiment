import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { C2paReader, InvalidSourceAssetError } from "adobe-js-state-machine/node";
import contract from "./fixtures/read-contract.json" with { type: "json" };

const path = fileURLToPath(new URL("./fixtures/read.jpg", import.meta.url));
const bytes = await readFile(path);
const config = { trust: false } as const;
const asset = () => ({ buffer: bytes, mimeType: "image/jpeg" });

test("file and buffer reads match the captured Adobe Reader report exactly", async () => {
  assert.equal(createHash("sha256").update(bytes).digest("hex"), contract.assetSha256);
  for (const source of [{ path }, asset()]) {
    const reader = await C2paReader.fromAsset(source, config);
    assert.ok(reader instanceof C2paReader);
    assert.equal(reader.activeLabel(), contract.manifestStore.active_manifest);
    assert.deepEqual(reader.json(), contract.manifestStore);
    const active = Object.entries(contract.manifestStore.manifests)
      .find(([label]) => label === contract.manifestStore.active_manifest)?.[1];
    assert.ok(active);
    assert.deepEqual(reader.getActive(), active);
    assert.equal(reader.remoteUrl(), "");
    assert.equal(reader.isEmbedded(), true);
    const copy = reader.json();
    copy.active_manifest = "not-the-active-manifest";
    assert.equal(reader.activeLabel(), contract.manifestStore.active_manifest);
  }
});

test("extensionless files are detected by their contents", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "adobe-reader-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = { path: join(directory, "asset") };
  await writeFile(source.path, bytes);
  const reader = await C2paReader.fromAsset(source, config);
  assert.deepEqual(reader?.json(), contract.manifestStore);
});

test("thumbnail extraction matches the baseline and an unsigned JPEG returns null", async () => {
  const reader = await C2paReader.fromAsset(asset(), config);
  assert.ok(reader);
  const result = await reader.resourceToAsset(contract.thumbnail.identifier, { buffer: null });
  assert.equal(result.bytes_written, contract.thumbnail.bytes);
  assert.equal(createHash("sha256").update(result.buffer).digest("hex"), contract.thumbnail.sha256);
  assert.equal(await C2paReader.fromAsset({ buffer: result.buffer, mimeType: "image/jpeg" }, config), null);
});

test("trust: false does not hide a tampered asset's integrity failure", async () => {
  assert.equal(bytes.readUInt16BE(bytes.length - 2), 0xffd9);
  const tampered = Buffer.from(bytes);
  tampered[tampered.length - 3] ^= 1;
  const reader = await C2paReader.fromAsset({ buffer: tampered, mimeType: "image/jpeg" }, config);
  assert.ok(reader);
  assert.equal(reader.json().validation_state, "Invalid");
});

test("missing buffer MIME type rejects with the Adobe error contract", async () => {
  // Exercise a JavaScript caller that did not satisfy the TypeScript contract.
  const source = { buffer: bytes };
  // @ts-expect-error mimeType is required on buffer inputs
  await assert.rejects(C2paReader.fromAsset(source, config), {
    name: "InvalidSourceAssetError",
    message: "mimeType is required when reading from a buffer asset.",
  });
  assert.ok(new InvalidSourceAssetError("test") instanceof Error);
});

test("unsupported formats, malformed JPEGs and I/O errors do not become null", async () => {
  await assert.rejects(C2paReader.fromAsset({ buffer: bytes, mimeType: "image/png" }, config),
    { name: "C2pa(UnsupportedType)" });
  await assert.rejects(C2paReader.fromAsset({ buffer: Buffer.from("not a JPEG"), mimeType: "image/jpeg" }, config));
  await assert.rejects(C2paReader.fromAsset({ path: join(tmpdir(), "adobe-reader-nonexistent", "missing.jpg") }, config),
    { code: "ENOENT" });
});

test("unimplemented trust policies and settings fail explicitly", async () => {
  // @ts-expect-error Default online trust policy is outside this proof
  await assert.rejects(C2paReader.fromAsset(asset()), /explicit trust: false/);
  // @ts-expect-error Trust lists are outside this proof
  await assert.rejects(C2paReader.fromAsset(asset(), { trust: true }), /explicit trust: false/);
  const extra = { trust: false, verify: {} } as const;
  await assert.rejects(C2paReader.fromAsset(asset(), extra), /Unsupported Adobe reader configuration: verify/);
});
