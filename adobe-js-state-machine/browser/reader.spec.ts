import { afterEach, describe, expect, test } from "vitest";
import { createAdobeC2pa, AdobeReader } from "adobe-js-state-machine/web";
import { createC2pa, Reader, Context } from "@contentauth/c2pa-web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import workerSrc from "c2pa-js-state-machine/worker-entry?worker&url";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import sourceUrl from "../test/fixtures/read.jpg?url";
import contract from "../test/fixtures/read-contract.json" with { type: "json" };

const clients: Awaited<ReturnType<typeof createAdobeC2pa>>[] = [];
const legacyClients: Awaited<ReturnType<typeof createC2pa>>[] = [];
const hash = async (bytes: Uint8Array) => Array.from(
  new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))),
  (byte) => byte.toString(16).padStart(2, "0"),
).join("");

afterEach(() => {
  for (const client of clients.splice(0)) {
    client.dispose();
    expect(client.liveResources).toBe(0);
  }
  for (const client of legacyClients.splice(0)) client.dispose();
});

describe.each(["inline", "worker"] as const)("%s Adobe basic reading", (mode) => {
  async function setup() {
    const blob = await (await fetch(sourceUrl)).blob();
    const client = await createAdobeC2pa({
      wasmSrc, trust: false,
      ...(mode === "worker" ? { workerSrc: new URL(workerSrc, location.href) } : {}),
    });
    clients.push(client);
    return { blob, client };
  }

  test("matches the captured Adobe report and the live pinned legacy reader", async () => {
    const { blob, client } = await setup();
    expect(await hash(new Uint8Array(await blob.arrayBuffer()))).toBe(contract.assetSha256);
    const reader = await client.reader.fromBlob("image/jpeg", blob);
    expect(reader).toBeInstanceOf(AdobeReader);
    if (!reader) throw new Error("Expected signed JPEG");
    expect(await reader.activeLabel()).toBe(contract.manifestStore.active_manifest);
    const active = Object.entries(contract.manifestStore.manifests)
      .find(([label]) => label === contract.manifestStore.active_manifest)?.[1];
    expect(active).toBeDefined();
    expect(await reader.activeManifest()).toEqual(active);
    expect(await reader.manifestStore()).toEqual(contract.manifestStore);
    expect(await reader.json()).toEqual(contract.manifestStore);

    const legacy = await createC2pa({ wasmSrc: legacyWasmSrc });
    legacyClients.push(legacy);
    const original = await Reader.fromBlob(legacy, "image/jpeg", blob, new Context({
      verify: { verifyTrust: false, ocspFetch: false },
      cawgTrust: { verifyTrustList: false },
    }));
    if (!original) throw new Error("Legacy reader did not read signed JPEG");
    try {
      expect(await reader.manifestStore()).toEqual(await original.manifestStore());
      expect(await reader.json()).toEqual(await original.json());
      const resource = await reader.resourceToBytes(contract.thumbnail.identifier);
      expect(resource).toEqual(await original.resourceToBytes(contract.thumbnail.identifier));
      expect(resource.length).toBe(contract.thumbnail.bytes);
      expect(await hash(resource)).toBe(contract.thumbnail.sha256);
      expect(await client.reader.fromBlob("image/jpeg", new Blob([new Uint8Array(resource)]))).toBeNull();
    } finally {
      await original.free();
      await reader.free();
    }
    expect(client.liveResources).toBe(0);
  });

  test("preserves failures, free and runtime disposal", async () => {
    const { blob, client } = await setup();
    await expect(client.reader.fromBlob("image/png", blob)).rejects.toThrow();
    await expect(client.reader.fromBlob("image/jpeg", new Blob(["not a JPEG"]))).rejects.toThrow();
    const reader = await client.reader.fromBlob("image/jpeg", blob);
    if (!reader) throw new Error("Expected signed JPEG");
    await expect(reader.resourceToBytes("self#jumbf=/missing")).rejects.toThrow();
    await reader.free();
    await reader.free();
    await expect(reader.manifestStore()).rejects.toThrow(/freed/);
    expect(client.liveResources).toBe(0);
    const owned = await client.reader.fromBlob("image/jpeg", blob);
    if (!owned) throw new Error("Expected signed JPEG");
    client.dispose();
    await expect(owned.activeManifest()).rejects.toThrow(/disposed/);
    await expect(client.reader.fromBlob("image/jpeg", blob)).rejects.toThrow(/disposed/);
  });

  test("trust: false retains the legacy tamper verdict", async () => {
    const { blob, client } = await setup();
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect(Array.from(bytes.slice(-2))).toEqual([0xff, 0xd9]);
    bytes[bytes.length - 3] ^= 1;
    const tampered = new Blob([bytes], { type: "image/jpeg" });
    const reader = await client.reader.fromBlob("image/jpeg", tampered);
    if (!reader) throw new Error("Tampering must not turn a signed asset into null");
    const legacy = await createC2pa({ wasmSrc: legacyWasmSrc });
    legacyClients.push(legacy);
    const original = await Reader.fromBlob(legacy, "image/jpeg", tampered, new Context({
      verify: { verifyTrust: false, ocspFetch: false },
      cawgTrust: { verifyTrustList: false },
    }));
    if (!original) throw new Error("Legacy reader did not read tampered JPEG");
    try {
      expect((await reader.manifestStore()).validation_state).toBe("Invalid");
      expect((await original.manifestStore()).validation_state).toBe("Invalid");
    } finally {
      await original.free();
      await reader.free();
    }
  });
});

test("unsupported Adobe configuration is rejected before loading Wasm", async () => {
  // @ts-expect-error Online trust is not implemented in this proof
  await expect(createAdobeC2pa({ wasmSrc, trust: true })).rejects.toThrow(/explicit trust: false/);
  const extra = { wasmSrc, trust: false, verify: {} } as const;
  await expect(createAdobeC2pa(extra)).rejects.toThrow(/Unsupported Adobe reader configuration: verify/);
});
