import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Reader, _native } from "../index.mjs";

const fixture = (name) => new URL(`../../c2pa-js-state-machine/browser/fixtures/${name}`, import.meta.url);
const asset = await readFile(fixture("detached-data-v2.jpg"));
const manifest = await readFile(fixture("detached-data-v2.c2pa"));
const legacy = JSON.parse(await readFile(fixture("detached-data-v2-report.json"), "utf8"));
const cert = new X509Certificate(await readFile(
  new URL("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der", import.meta.url)));
const settings = {
  trust: { anchors: [{ trust_anchors: cert.toString(), trust_kind: "manifest", trust_uri: "system_anchors" }] },
  verify: { verify_trust: true, ocsp_fetch: false },
};
const options = { now: () => 1_800_000_000_000, fetch: () => assert.fail("detached reads must not fetch") };
const data = await readFile(fixture("ingredient-data.json"));
const svg = await readFile(fixture("generator-icon.svg"));

// Adapted from pinned c2pa-node Reader.spec.ts's detached buffer/file cases.
// The real c2pa-rs generator validates this genuine store-free resource fixture
// as Trusted and records its complete JSON, rather than mocking a Reader.
test("detached buffer/file/async sources match the complete trusted real-c2pa-rs report", async () => {
  const directory = await mkdtemp(join(tmpdir(), "c2pa-node-detached-"));
  try {
    const path = join(directory, "asset.dat");
    await writeFile(path, asset);
    assert.equal(await Reader.fromAsset({ path }, settings, options), null);
    assert.equal(await Reader.fromAsset({ buffer: asset }, settings, options), null);
    let reads = 0;
    const sources = [
      { path },
      { buffer: asset, mimeType: "image/jpeg" },
      { size: asset.length, mimeType: "image/jpeg",
        async read(start, len) { reads++; return asset.subarray(start, start + len) } },
    ];
    for (const source of sources) {
      const reader = await Reader.fromManifestDataAndAsset(manifest, source, settings, options);
      if (source.path) await rm(source.path);
      const completedReads = reads;
      assert.deepEqual(reader.json(), legacy);
      assert.equal(reader.json().validation_state, "Trusted");
      assert.equal(reader.isEmbedded(), false);
      assert.equal(reader.remoteUrl(), "");
      const ingredients = reader.getActive().ingredients;
      for (const ingredient of ingredients) {
        assert.deepEqual(await reader.resourceToAsset(ingredient.data.identifier, { buffer: null }),
          { buffer: data, bytes_written: data.length });
      }
      assert.deepEqual((await reader.resourceToAsset(ingredients[0].thumbnail.identifier, { buffer: null })).buffer, svg);
      assert.equal(reads, completedReads);
    }
    assert.ok(reads > 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("detached asset tampering remains invalid and resource extraction cannot grant trust", async () => {
  const changed = Buffer.concat([asset, Buffer.from([0])]);
  const reader = await Reader.fromManifestDataAndAsset(manifest, { buffer: changed }, settings, options);
  const before = reader.json();
  assert.equal(before.validation_state, "Invalid");
  assert.ok(before.validation_status.some((status) => status.code === "assertion.dataHash.mismatch"));
  const uri = reader.getActive().ingredients[0].data.identifier;
  assert.deepEqual((await reader.resourceToAsset(uri, { buffer: null })).buffer, data);
  assert.deepEqual(reader.json(), before);
});

test("malformed explicit detached bytes never fall back to a valid embedded store", async () => {
  const embedded = await readFile(fixture("ingredient-data-v2.jpg"));
  assert.equal((await Reader.fromAsset({ buffer: embedded }, settings, options)).json().validation_state, "Trusted");
  for (const bytes of [Buffer.alloc(0), Buffer.from([1, 2, 3]), manifest.subarray(0, 32)]) {
    await assert.rejects(Reader.fromManifestDataAndAsset(bytes, { buffer: embedded }, settings, options));
    await assert.rejects(Reader.fromManifestDataAndAsset(bytes, { buffer: asset }, settings, options));
  }
  const reader = await Reader.fromManifestDataAndAsset(manifest, { buffer: asset }, settings, options);
  assert.deepEqual(reader.json(), legacy);
});

test("an unrelated valid detached store takes precedence and reports the supplied label and binding failure", async () => {
  const embedded = await readFile(fixture("ingredient-data-v2.jpg"));
  const embeddedReader = await Reader.fromAsset({ buffer: embedded }, settings, options);
  assert.notEqual(embeddedReader.activeLabel(), legacy.active_manifest);
  const reader = await Reader.fromManifestDataAndAsset(manifest, { buffer: embedded }, settings, options);
  assert.equal(reader.activeLabel(), legacy.active_manifest);
  assert.equal(reader.isEmbedded(), false);
  assert.equal(reader.json().validation_state, "Invalid");
  assert.ok(reader.json().validation_status.some((status) => status.code === "assertion.dataHash.mismatch"));
});

test("manifest buffers are snapshotted before asynchronous source reads and concurrent sessions stay isolated", async () => {
  const bytes = Buffer.from(manifest);
  const pending = Reader.fromManifestDataAndAsset(bytes, {
    size: asset.length,
    mimeType: "image/jpeg",
    async read(start, len) {
      await new Promise((resolve) => setImmediate(resolve));
      return asset.subarray(start, start + len);
    },
  }, settings, options);
  bytes.fill(0);
  const [trusted, untrusted] = await Promise.all([
    pending,
    Reader.fromManifestDataAndAsset(manifest, { buffer: asset }, { verify: { ocsp_fetch: false } }, options),
  ]);
  assert.deepEqual(trusted.json(), legacy);
  assert.notEqual(untrusted.json().validation_state, "Trusted");
  assert.equal(untrusted.isEmbedded(), false);
  assert.deepEqual(trusted.json(), legacy);
});

test("invalid detached inputs and source failures reject explicitly and allow later recovery", async () => {
  for (const bad of [null, undefined, "bad", new Uint8Array(manifest)]) {
    await assert.rejects(Reader.fromManifestDataAndAsset(bad, { buffer: asset }, settings, options), TypeError);
  }
  assert.throws(() => _native.sessionNew("image/jpeg", undefined, "bad"), TypeError);
  await assert.rejects(Reader.fromManifestDataAndAsset(manifest,
    { buffer: asset, mimeType: "image/png" }, settings, options), { name: "C2pa(UnsupportedType)" });
  await assert.rejects(Reader.fromManifestDataAndAsset(manifest,
    { buffer: asset }, "{bad json", options), (error) => error.name.startsWith("C2pa(BadParam("));
  await assert.rejects(Reader.fromManifestDataAndAsset(manifest,
    { path: "/no/such/detached-asset.jpg" }, settings, options), { code: "ENOENT" });
  await assert.rejects(Reader.fromManifestDataAndAsset(manifest, {
    size: asset.length, mimeType: "image/jpeg",
    async read() { throw new Error("source unavailable") },
  }, settings, options), /source unavailable/);
  assert.deepEqual((await Reader.fromManifestDataAndAsset(manifest,
    { buffer: asset }, settings, options)).json(), legacy);
});
