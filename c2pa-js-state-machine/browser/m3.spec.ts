import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { Builder, Context, createC2pa, Reader, type Runtime, type Signer } from "c2pa-js-state-machine/inline";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };

const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const source = () => new Blob([bytes(fixtures.source)], { type: "image/jpeg" });
function withoutEmbeddedC2paStore(input: Uint8Array): Uint8Array {
  const chunks = [input.subarray(0, 2)];
  let offset = 2;
  let removed = 0;
  while (offset < input.length && input[offset] === 0xff) {
    const markerStart = offset;
    while (input[offset] === 0xff) offset++;
    const marker = input[offset++];
    if (marker === 0xda || marker === 0xd9) {
      chunks.push(input.subarray(markerStart));
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      chunks.push(input.subarray(markerStart, offset));
      continue;
    }
    const length = (input[offset] << 8) | input[offset + 1];
    const end = offset + length;
    const isC2paApp11 = marker === 0xeb &&
      input[offset + 2] === 0x4a && input[offset + 3] === 0x50 &&
      input[offset + 4] === 0x02 && input[offset + 5] === 0x11;
    if (isC2paApp11) removed++;
    else chunks.push(input.subarray(markerStart, end));
    offset = end;
  }
  if (removed !== 1) throw new Error(`Expected one C2PA APP11 segment, found ${removed}`);
  const output = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
  let cursor = 0;
  for (const chunk of chunks) {
    output.set(chunk, cursor);
    cursor += chunk.length;
  }
  return output;
}
const storeFreeBytes = () => withoutEmbeddedC2paStore(bytes(fixtures.source));
const storeFreeSource = () => new Blob([new Uint8Array(storeFreeBytes())], { type: "image/jpeg" });
const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
const trusted = () => new Context({ trust: { trustAnchors: root }, verify: { ocspFetch: false, verifyTrust: true } });
const runtimes: Runtime[] = [];

async function runtime() {
  const instance = await createC2pa({ wasmSrc });
  runtimes.push(instance);
  return instance;
}

async function signer(): Promise<Signer> {
  const der = bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, ""));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return {
    alg: "es256",
    certs: [bytes(fixtures.cert)],
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data),
      ));
    },
  };
}

describe("M3 detached manifests", () => {
  beforeEach(() => { vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-01T00:00:00Z")) });
  afterEach(() => {
    for (const instance of runtimes.splice(0)) {
      instance.dispose();
      expect(instance.liveResources).toBe(0);
    }
    vi.restoreAllMocks();
  });

  test("builds and reads a manifest detached from an unchanged, store-free asset", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    let output: { asset: Uint8Array; manifest: Uint8Array };
    const sourceBytes = storeFreeBytes();
    try { output = await builder.signDetached(await signer(), storeFreeSource()) }
    finally { await builder.free() }

    expect(output.asset).toEqual(sourceBytes);
    const asset = new Blob([new Uint8Array(output.asset)], { type: "image/jpeg" });
    const withoutDetachedStore = await Reader.fromBlob(client, "image/jpeg", asset, trusted());
    expect(await withoutDetachedStore?.activeLabel()).toBeUndefined();
    const reader = await Reader.fromBlob(client, "image/jpeg", asset, trusted(), output.manifest);
    expect(reader).not.toBeNull();
    const report = await reader!.manifestStore();
    expect(report.validation_state, JSON.stringify(report.validation_results)).toBe("Trusted");
    expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
  });

  test("does not trust a detached manifest after the asset changes", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    let output: { asset: Uint8Array; manifest: Uint8Array };
    try { output = await builder.signDetached(await signer(), storeFreeSource()) }
    finally { await builder.free() }

    const changedAsset = new Uint8Array(output.asset.length + 1);
    changedAsset.set(output.asset);
    const reader = await Reader.fromBlob(
      client,
      "image/jpeg",
      new Blob([changedAsset], { type: "image/jpeg" }),
      trusted(),
      output.manifest,
    );
    expect(reader).not.toBeNull();
    const report = await reader!.manifestStore();
    expect(report.validation_state, JSON.stringify(report.validation_results)).toBe("Invalid");
  });

  test("rejects malformed detached store bytes instead of falling back to embedded reading", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    let output: { asset: Uint8Array; manifest: Uint8Array };
    try { output = await builder.sign(await signer(), "image/jpeg", source()) }
    finally { await builder.free() }

    await expect(Reader.fromBlob(
      client,
      "image/jpeg",
      new Blob([new Uint8Array(output.asset)], { type: "image/jpeg" }),
      trusted(),
      Uint8Array.of(1, 2, 3),
    )).rejects.toThrow();
  });
});
