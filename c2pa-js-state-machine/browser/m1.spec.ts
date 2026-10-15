import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createC2pa, Builder, Reader, Context, type Runtime, type Signer } from "c2pa-js-state-machine/inline";
import { createC2pa as createLegacy, Reader as LegacyReader, Context as LegacyContext } from "@contentauth/c2pa-web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };
import { BrowserReader } from "../.cache/generated/state_machine.js";
import noAlgorithmSrc from "test/assets/no_alg.jpg?url";
import unsignedSrc from "test/assets/C_with_CAWG_data_thumbnail.jpg?url";
import legacyAssetSrc from "test/assets/C_with_CAWG_data.jpg?url";
import legacyRoot from "test/trust/anchor-correct.pem?raw";
import legacyIdentityRoot from "test/trust/anchor-cawg.pem?raw";

const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const source = () => new Blob([bytes(fixtures.source)], { type: "image/jpeg" });
const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
const trusted = () => new Context({ trust: { trustAnchors: root }, verify: { ocspFetch: false, verifyTrust: true } });
const runtimes: Runtime[] = [];
async function runtime() { const value = await createC2pa({ wasmSrc }); runtimes.push(value); return value }
async function signer(onSign: () => void = () => {}): Promise<Signer> {
  const der = bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, ""));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  expect(key.extractable).toBe(false);
  return { alg: "es256", certs: [bytes(fixtures.cert)], async sign(data) {
    onSign();
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
    expect(signature.length).toBe(64);
    return signature;
  } };
}
async function signed(client: Runtime) {
  const builder = await Builder.fromDefinition(client, fixtures.definition);
  try { return await builder.sign(await signer(), "image/jpeg", source()) }
  finally { await builder.free() }
}
function yielding(blob: Blob, id: string, log: string[]): Blob {
  class Slice extends Blob {
    override async arrayBuffer(): Promise<ArrayBuffer> {
      log.push(`${id}:start`);
      await new Promise((resolve) => setTimeout(resolve, 0));
      const result = await super.arrayBuffer();
      log.push(`${id}:end`);
      return result;
    }
  }
  class Source extends Blob {
    override slice(start?: number, end?: number, type?: string): Blob {
      return new Slice([super.slice(start, end, type)]);
    }
  }
  return new Source([blob], { type: blob.type });
}
function interleaved(log: string[]) {
  expect(log.indexOf("a:start")).toBeLessThan(log.indexOf("b:end"));
  expect(log.indexOf("b:start")).toBeLessThan(log.indexOf("a:end"));
  expect(log.filter((entry) => entry.endsWith(":start")).length).toBeGreaterThanOrEqual(2);
}

describe("M1", () => {
  beforeEach(() => { vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-01T00:00:00Z")) });
  afterEach(() => {
    for (const client of runtimes.splice(0)) { client.dispose(); expect(client.liveResources).toBe(0) }
    vi.restoreAllMocks();
  });
  test("initialization failure recovers and unsupported loader configuration is explicit", async () => {
    await expect(createC2pa({ wasmSrc: "data:application/wasm;base64,AA==" })).rejects.toThrow();
    const client = await runtime();
    expect(client.liveResources).toBe(0);
    await expect(createC2pa({ wasmSrc: "different.wasm" })).rejects.toThrow(/different resource/);
    await expect(createC2pa({ wasmSrc, workerSrc: new URL("https://example.invalid/worker") })).rejects.toThrow(/inline-only/);
  });
  test("WebCrypto signs a JPEG and real validation distinguishes trusted untrusted and tampered assets", async () => {
    const client = await runtime();
    const output = await signed(client);
    expect(output.asset).toBeInstanceOf(Uint8Array);
    expect(output.manifest).toBeInstanceOf(Uint8Array);
    expect(output.manifest.length).toBeGreaterThan(0);
    const blob = new Blob([new Uint8Array(output.asset)], { type: "image/jpeg" });
    const reader = await Reader.fromBlob(client, undefined, blob, trusted());
    expect(reader).not.toBeNull();
    expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
    expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
    expect((await reader!.json()).active_manifest).toBe(await reader!.activeLabel());
    const untrusted = await Reader.fromBlob(client, "image/jpeg", blob);
    expect((await untrusted!.manifestStore()).validation_state).toBe("Valid");
    const changed = new Uint8Array(output.asset);
    changed[changed.length - 4] ^= 1;
    const invalid = await Reader.fromBlob(client, "image/jpeg", new Blob([changed]), trusted());
    const report = await invalid!.manifestStore();
    expect(report.validation_state).toBe("Invalid");
    expect(report.validation_status?.some((status) => status.code === "assertion.dataHash.mismatch")).toBe(true);
  });
  test("legacy and state-machine assets cross-read with matching validation semantics", async () => {
    const client = await runtime();
    const createURL = URL.createObjectURL.bind(URL);
    let clocked = false;
    vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
      if (blob instanceof Blob && ["text/javascript", "application/javascript"].includes(blob.type.split(";")[0])) {
        clocked = true;
        const frozen = Date.parse("2026-09-01T00:00:00Z");
        const clock = `const NativeDate = Date; Date = class extends NativeDate {
          constructor(...args) { super(...(args.length ? args : [${frozen}])); }
          static now() { return ${frozen}; }
        };\n`;
        return createURL(new Blob([clock, blob], { type: blob.type }));
      }
      return createURL(blob);
    });
    const legacy = await createLegacy({ wasmSrc: legacyWasmSrc });
    try {
      expect(clocked).toBe(true);
      const output = await signed(client);
      const context = new LegacyContext({ trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } });
      const reader = await LegacyReader.fromBlob(legacy, "image/jpeg", new Blob([new Uint8Array(output.asset)]), context);
      expect(reader).not.toBeNull();
      expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
      expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
      await reader!.free();
      const asset = await (await fetch(legacyAssetSrc)).blob();
      const stateContext = new Context({ trust: { trustAnchors: legacyRoot },
        cawgTrust: { trustAnchors: legacyIdentityRoot }, verify: { verifyTrust: true, ocspFetch: false } });
      const legacyContext = new LegacyContext({ trust: { trustAnchors: legacyRoot },
        cawgTrust: { trustAnchors: legacyIdentityRoot }, verify: { verifyTrust: true, ocspFetch: false } });
      const [oldReader, newReader] = await Promise.all([
        LegacyReader.fromBlob(legacy, "image/jpeg", asset, legacyContext),
        Reader.fromBlob(client, "image/jpeg", asset, stateContext),
      ]);
      expect((await newReader!.manifestStore()).validation_state).toBe("Trusted");
      expect((await oldReader!.manifestStore()).validation_state).toBe("Trusted");
      expect(await newReader!.activeLabel()).toBe(await oldReader!.activeLabel());
      await oldReader!.free();
    } finally { legacy.dispose() }
  });
  test("two reads suspend and interleave at actual Blob request boundaries", async () => {
    const client = await runtime();
    const output = await signed(client);
    const log: string[] = [];
    const blob = new Blob([new Uint8Array(output.asset)]);
    const readers = await Promise.all(["a", "b"].map((id) => Reader.fromBlob(client, "image/jpeg", yielding(blob, id, log), trusted())));
    interleaved(log);
    for (const reader of readers) expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
  });
  test("two builds suspend and interleave without duplicate signing callbacks", async () => {
    const client = await runtime();
    const log: string[] = [];
    const counts = [0, 0];
    const builders = await Promise.all([Builder.fromDefinition(client, fixtures.definition), Builder.fromDefinition(client, fixtures.definition)]);
    const signers = await Promise.all(counts.map((_, index) => signer(() => { counts[index]++ })));
    const outputs = await Promise.all(builders.map((builder, index) => builder.sign(signers[index], "image/jpeg", yielding(source(), index ? "b" : "a", log))));
    interleaved(log);
    expect(counts).toEqual([1, 1]);
    for (const output of outputs) {
      const reader = await Reader.fromBlob(client, "image/jpeg", new Blob([new Uint8Array(output.asset)]), trusted());
      expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
    }
  });
  test("signer and Blob failures do not poison subsequent operations", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    const good = await signer();
    let calls = 0;
    await expect(builder.sign({ ...good, async sign() { calls++; throw new Error("signer failed") } }, "image/jpeg", source())).rejects.toThrow(/signer failed/);
    expect(calls).toBe(1);
    class FailedSlice extends Blob { override async arrayBuffer(): Promise<ArrayBuffer> { throw new Error("blob failed") } }
    class FailedBlob extends Blob { override slice(): Blob { return new FailedSlice() } }
    await expect(Reader.fromBlob(client, "image/jpeg", new FailedBlob([source()]))).rejects.toThrow(/blob failed/);
    await expect(builder.sign(good, "image/jpeg", new FailedBlob([source()]))).rejects.toThrow(/blob failed/);
    const recovered = await builder.sign(good, "image/jpeg", source());
    const reader = await Reader.fromBlob(client, "image/jpeg", new Blob([new Uint8Array(recovered.asset)]), trusted());
    expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
  });
  test("invalid definitions missing timestamp services and unsupported settings reject", async () => {
    const client = await runtime();
    await expect(Builder.fromDefinition(client, { ...fixtures.definition, unexpected: true })).rejects.toThrow();
    await expect(Builder.fromDefinition(client, { ...fixtures.definition, instance_id: null })).rejects.toThrow();
    const builder = await Builder.fromDefinition(client, { ...fixtures.definition, tsa_url: "https://example.invalid/tsa" });
    await expect(builder.sign(await signer(), "image/jpeg", source())).rejects.toThrow(/timestamp/i);
    await expect(Reader.fromBlob(client, "image/jpeg", source(), new Context({ verify: { ocspFetch: true } }))).rejects.toThrow(/Unsupported reader setting/);
    await expect(Reader.fromBlob(client, "image/jpeg", source(), new Context({ verify: { remoteManifestFetch: true } }))).rejects.toThrow(/Unsupported reader setting/);
    const legacy = await (await fetch(legacyAssetSrc)).blob();
    const defaultTrust = await Reader.fromBlob(client, "image/jpeg", legacy, new Context({
      trust: { trustAnchors: legacyRoot }, cawgTrust: { trustAnchors: legacyIdentityRoot },
    }));
    expect((await defaultTrust!.manifestStore()).validation_state).toBe("Trusted");
    expect(await Reader.fromBlob(client, "image/jpeg", await (await fetch(unsignedSrc)).blob())).toBeNull();
  });
  test("free and disposal safely drain an in-flight builder without publishing a result", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    expect(Object.keys(builder)).toEqual([]);
    let release!: () => void;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve });
    const gate = new Promise<void>((resolve) => { release = resolve });
    const good = await signer();
    let calls = 0;
    const pending = builder.sign({ ...good, async sign(data) { calls++; entered(); await gate; return good.sign(data) } }, "image/jpeg", source());
    const rejected = expect(pending).rejects.toThrow(/disposed/);
    await started;
    await expect(builder.sign(good, "image/jpeg", source())).rejects.toThrow(/in-flight/);
    await builder.free();
    client.dispose();
    release();
    await rejected;
    expect(calls).toBe(1);
    expect(client.liveResources).toBe(0);
    await expect(builder.sign(good, "image/jpeg", source())).rejects.toThrow(/disposed/);
  });
  test("disposal during a pending read releases its eventual FFI handle", async () => {
    const client = await runtime();
    const output = await signed(client);
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve });
    const gate = new Promise<void>((resolve) => { release = resolve });
    class Slice extends Blob { override async arrayBuffer(): Promise<ArrayBuffer> { entered(); await gate; return super.arrayBuffer() } }
    class Source extends Blob { override slice(start?: number, end?: number): Blob { return new Slice([super.slice(start, end)]) } }
    const pending = Reader.fromBlob(client, "image/jpeg", new Source([new Uint8Array(output.asset)]), trusted());
    const rejected = expect(pending).rejects.toThrow(/disposed/);
    await started;
    client.dispose();
    release();
    await rejected;
    expect(client.liveResources).toBe(0);
    await expect(Reader.fromBlob(client, "image/jpeg", source())).rejects.toThrow(/disposed/);
  });
  test("missing claim algorithm is rejected at the compatibility boundary", async () => {
    await runtime();
    await expect(BrowserReader.fromBlob("image/jpeg", await (await fetch(noAlgorithmSrc)).blob()))
      .rejects.toBe("C2pa(UnknownAlgorithm)");
  });
});
