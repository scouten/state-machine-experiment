import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { C2paReader, type AdobeReadConfig } from "adobe-js-state-machine/node";
import corpus from "./fixtures/corpus.json" with { type: "json" };
import { expectedReport, hasTimestampPolicyDifference } from "./report-contract.ts";

const anchors = await readFile(new URL("./fixtures/trust.txt", import.meta.url), "utf8");
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

test("corpus includes independent assets, containers, claim versions and trust verdicts", () => {
  assert.ok(new Set(corpus.map((item) => item.file)).size >= 7);
  assert.deepEqual(new Set(corpus.map((item) => item.mimeType)), new Set(["image/jpeg", "image/tiff"]));
  assert.deepEqual(new Set(corpus.map((item) => item.manifestStore?.validation_state)),
    new Set(["Valid", "Trusted", undefined]));
});

for (const item of corpus) {
  test(`Adobe Node corpus: ${item.name}${hasTimestampPolicyDifference(item) ? " (explicit TSA-policy difference)" : ""}`, async () => {
    const path = fileURLToPath(new URL(`./fixtures/${item.file}`, import.meta.url));
    const bytes = await readFile(path);
    assert.equal(hash(bytes), item.assetSha256);
    const config: AdobeReadConfig = item.policy === "disabled"
      ? { trust: false } : { trust: { trust: { trustAnchors: item.policy === "trusted" ? anchors : [] } } };
    for (const asset of [{ path }, { buffer: bytes, mimeType: item.mimeType }]) {
      const reader = await C2paReader.fromAsset(asset, config);
      assert.deepEqual(reader?.json() ?? null, expectedReport(item));
      if (hasTimestampPolicyDifference(item)) assert.notDeepEqual(reader?.json(), item.manifestStore);
      if (!reader) { assert.equal(item.manifestStore, null); continue }
      assert.equal(reader.activeLabel(), item.manifestStore?.active_manifest);
      const active = Object.entries(item.manifestStore?.manifests ?? {})
        .find(([label]) => label === reader.activeLabel())?.[1];
      assert.deepEqual(reader.getActive(), active);
      for (const resource of item.resources) {
        const result = await reader.resourceToAsset(resource.identifier, { buffer: null });
        assert.equal(result.bytes_written, resource.bytes);
        assert.equal(hash(result.buffer), resource.sha256);
      }
    }
    if (item.manifestStore !== null && item.mimeType === "image/jpeg") {
      assert.equal(bytes.readUInt16BE(bytes.length - 2), 0xffd9);
      const tampered = Buffer.from(bytes);
      tampered[tampered.length - 3] ^= 1;
      const reader = await C2paReader.fromAsset({ buffer: tampered, mimeType: item.mimeType }, config);
      assert.equal(reader?.json().validation_state, "Invalid");
    }
  });

}

test("concurrent trust policies remain isolated", async () => {
  const path = fileURLToPath(new URL("./fixtures/read.jpg", import.meta.url));
  const readers = await Promise.all([
    C2paReader.fromAsset({ path }, { trust: { trust: { trustAnchors: [anchors] } } }),
    C2paReader.fromAsset({ path }, { trust: { trust: { trustAnchors: [] } } }),
  ]);
  assert.deepEqual(readers.map((reader) => reader?.json().validation_state), ["Trusted", "Valid"]);
});

test("unsupported trust downloads and malformed anchor policies reject explicitly", async () => {
  const asset = { path: fileURLToPath(new URL("./fixtures/read.jpg", import.meta.url)) };
  await assert.rejects(C2paReader.fromAsset(asset, {
    trust: { trust: { trustAnchors: "https://example.invalid/anchors.pem" } },
  }), /Unsupported Adobe trust setting/);
  await assert.rejects(C2paReader.fromAsset(asset, {
    trust: { trust: { trustAnchors: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----" } },
  }));
});
