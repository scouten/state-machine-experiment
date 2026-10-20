import { afterEach, describe, expect, test } from "vitest";
import { createAdobeC2pa } from "adobe-js-state-machine/web";
import { createC2pa, Reader, Context } from "@contentauth/c2pa-web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import workerSrc from "c2pa-js-state-machine/worker-entry?worker&url";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import anchors from "../test/fixtures/trust.txt?raw";
import corpus from "../test/fixtures/corpus.json" with { type: "json" };
import { expectedReport, hasTimestampPolicyDifference } from "../test/report-contract.ts";

const sources = import.meta.glob<string>("../test/fixtures/**/*.{jpg,tif}", {
  query: "?url", import: "default", eager: true,
});
const clients: { dispose(): void }[] = [];
afterEach(() => { for (const client of clients.splice(0)) client.dispose() });
const hash = async (bytes: Uint8Array) => Array.from(new Uint8Array(
  await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
), (byte) => byte.toString(16).padStart(2, "0")).join("");

describe.each(["inline", "worker"] as const)("%s Adobe corpus", (mode) => {
  test.each(corpus)("$name differential report/resource contract", async (item) => {
    const url = sources[`../test/fixtures/${item.file}`];
    if (!url) throw new Error(`Missing corpus asset: ${item.file}`);
    const blob = await (await fetch(url)).blob();
    expect(await hash(new Uint8Array(await blob.arrayBuffer()))).toBe(item.assetSha256);
    const trustAnchors = item.policy === "trusted" ? anchors : [];
    const client = await createAdobeC2pa({
      wasmSrc,
      trust: item.policy === "disabled" ? false : { trust: { trustAnchors } },
      ...(mode === "worker" ? { workerSrc: new URL(workerSrc, location.href) } : {}),
    });
    clients.push(client);
    const legacy = await createC2pa({ wasmSrc: legacyWasmSrc });
    clients.push(legacy);
    const original = await Reader.fromBlob(legacy, item.mimeType, blob, new Context({
      verify: { verifyTrust: item.policy !== "disabled", ocspFetch: false },
      ...(item.policy === "disabled" ? { cawgTrust: { verifyTrustList: false } } : { trust: { trustAnchors } }),
    }));
    const reader = await client.reader.fromBlob(item.mimeType, blob);
    if (item.manifestStore === null) {
      expect(reader).toBeNull();
      expect(original).toBeNull();
      return;
    }
    if (!reader || !original) throw new Error("Signed corpus input must not become null");
    try {
      expect(await reader.manifestStore()).toEqual(expectedReport(item));
      expect(await reader.json()).toEqual(expectedReport(item));
      expect(await original.json()).toEqual(item.manifestStore);
      expect(await original.manifestStore()).toEqual(item.manifestStore);
      if (hasTimestampPolicyDifference(item))
        expect(await reader.manifestStore()).not.toEqual(await original.manifestStore());
      expect(await reader.activeManifest()).toEqual(await original.activeManifest());
      expect(await reader.activeLabel()).toBe(item.manifestStore.active_manifest);
      for (const resource of item.resources) {
        const bytes = await reader.resourceToBytes(resource.identifier);
        expect(bytes).toEqual(await original.resourceToBytes(resource.identifier));
        expect(bytes.length).toBe(resource.bytes);
        expect(await hash(bytes)).toBe(resource.sha256);
      }
    } finally {
      await reader.free();
      await original.free();
    }
    expect(client.liveResources).toBe(0);
    if (item.mimeType === "image/jpeg") {
      const bytes = new Uint8Array(await blob.arrayBuffer());
      expect(Array.from(bytes.slice(-2))).toEqual([0xff, 0xd9]);
      bytes[bytes.length - 3] ^= 1;
      const tampered = new Blob([bytes], { type: "image/jpeg" });
      const modified = await client.reader.fromBlob(item.mimeType, tampered);
      const reference = await Reader.fromBlob(legacy, item.mimeType, tampered, new Context({
        verify: { verifyTrust: item.policy !== "disabled", ocspFetch: false },
        ...(item.policy === "disabled" ? { cawgTrust: { verifyTrustList: false } } : { trust: { trustAnchors } }),
      }));
      if (!modified || !reference) throw new Error("Tampering must not become an unsigned asset");
      try {
        expect((await modified.manifestStore()).validation_state).toBe("Invalid");
        expect((await reference.manifestStore()).validation_state).toBe("Invalid");
      } finally {
        await modified.free();
        await reference.free();
      }
    }
  });

  test("factory trust is snapshotted and concurrent policies are isolated", async () => {
    const list = [anchors];
    const config = {
      wasmSrc, trust: { trust: { trustAnchors: list } },
      ...(mode === "worker" ? { workerSrc: new URL(workerSrc, location.href) } : {}),
    };
    const trusted = await createAdobeC2pa(config);
    clients.push(trusted);
    list.length = 0;
    const untrusted = await createAdobeC2pa(config);
    clients.push(untrusted);
    const blob = await (await fetch(sources["../test/fixtures/read.jpg"])).blob();
    const readers = await Promise.all([
      trusted.reader.fromBlob("image/jpeg", blob),
      untrusted.reader.fromBlob("image/jpeg", blob),
    ]);
    try {
      expect(await Promise.all(readers.map(async (reader) =>
        (await reader?.manifestStore())?.validation_state))).toEqual(["Trusted", "Valid"]);
    } finally {
      await Promise.all(readers.map((reader) => reader?.free()));
    }
  });
});
