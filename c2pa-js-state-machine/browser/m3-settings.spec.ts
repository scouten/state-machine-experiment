import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import * as inline from "c2pa-js-state-machine/inline";
import * as worker from "c2pa-js-state-machine/worker";
import { createC2pa as createLegacy, Reader as LegacyReader, Context as LegacyContext } from "@contentauth/c2pa-web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import workerSrc from "./clocked-worker.ts?worker&url";
import unclockedWorkerSrc from "c2pa-js-state-machine/worker-entry?worker&url";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };

const bytes = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
const settings = () => ({ trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } });
const clients: { dispose(): void }[] = [];
async function setup() {
  const configured = settings();
  const plain = await inline.createC2pa({ wasmSrc });
  clients.push(plain);
  const builder = await inline.Builder.fromDefinition(plain, fixtures.definition);
  const key = await crypto.subtle.importKey("pkcs8", bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, "")),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const result = await builder.sign({
    alg: "es256", certs: [bytes(fixtures.cert)], async sign(data) {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
    },
  }, "image/jpeg", new Blob([bytes(fixtures.source)]));
  await builder.free();
  const a = await inline.createC2pa({ wasmSrc, settings: configured });
  const b = await worker.createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href), settings: configured });
  const legacy = await createLegacy({ wasmSrc: legacyWasmSrc, settings: settings() });
  clients.push(a, b, legacy);
  return { a, b, legacy, plain, configured, asset: new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" }) };
}
async function state(reader: { json(): Promise<{ validation_state?: string }>; free(): Promise<void> } | null) {
  expect(reader).not.toBeNull();
  try { return (await reader!.json()).validation_state }
  finally { await reader!.free() }
}

describe("M3 reader factory settings", () => {
  beforeEach(() => { vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-01T00:00:00Z")) });
  afterEach(() => { for (const client of clients.splice(0)) client.dispose(); vi.restoreAllMocks() });
  test("overlapping readers keep conflicting Contexts isolated and share each Context resolution", async () => {
    const { a, b, legacy, asset } = await setup();
    const options = [
      settings(),
      { trust: { trustAnchors: "" }, verify: { verifyTrust: true, ocspFetch: false } },
      { ...settings(), verify: { verifyTrust: false, ocspFetch: false } },
    ];
    const expected = [];
    for (const option of options) {
      const reader = await LegacyReader.fromBlob(legacy, undefined, asset, new LegacyContext(option));
      expected.push(await reader!.manifestStore());
      await reader!.free();
    }
    expect(expected.map((store) => store.validation_state)).toEqual(["Trusted", "Valid", "Valid"]);
    for (const read of [
      (context: inline.Context) => inline.Reader.fromBlob(a, undefined, asset, context),
      (context: inline.Context) => worker.Reader.fromBlob(b, undefined, asset, context),
      (context: inline.Context) => LegacyReader.fromBlob(legacy, undefined, asset, context),
    ]) {
      const contexts = options.map((option) => new inline.Context(option));
      const spy = vi.spyOn(contexts[0]!, "toJson");
      const readers = await Promise.all([read(contexts[0]!), read(contexts[1]!), read(contexts[2]!), read(contexts[0]!)]);
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy.mock.results[0]!.value).toBe(spy.mock.results[1]!.value);
      for (const [index, reader] of readers.entries()) {
        expect(await reader!.manifestStore()).toEqual(expected[index % 3]);
        await reader!.free();
      }
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("a resolved Context keeps its cached trust policy after caller settings mutate on both runtimes", async () => {
    const { a, b, legacy, asset } = await setup();
    for (const read of [
      (context: inline.Context) => inline.Reader.fromBlob(a, "image/jpeg", asset, context),
      (context: inline.Context) => worker.Reader.fromBlob(b, "image/jpeg", asset, context),
      (context: inline.Context) => LegacyReader.fromBlob(legacy, "image/jpeg", asset, context),
    ]) {
      const options = settings();
      const context = new inline.Context(options);
      const first = await read(context);
      const expected = await first!.manifestStore();
      expect(expected.validation_state).toBe("Trusted");
      await first!.free();
      const resolved = context.toJson();
      options.verify.verifyTrust = false;
      options.trust.trustAnchors = "";
      const later = await read(context);
      expect(await later!.manifestStore()).toEqual(expected);
      expect(context.toJson()).toBe(resolved);
      await later!.free();
      expect(await state(await read(new inline.Context(options)))).toBe("Valid");
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("caller Context resolution failures are observable and do not poison later reads", async () => {
    const { a, b, legacy, asset } = await setup();
    for (const read of [
      (context: inline.Context) => inline.Reader.fromBlob(a, "image/jpeg", asset, context),
      (context: inline.Context) => worker.Reader.fromBlob(b, "image/jpeg", asset, context),
      (context: inline.Context) => LegacyReader.fromBlob(legacy, "image/jpeg", asset, context),
    ]) {
      const context = new inline.Context(settings());
      const spy = vi.spyOn(context, "toJson").mockRejectedValueOnce(new Error("Context resolution failed"));
      await expect(read(context)).rejects.toThrow("Context resolution failed");
      expect(await state(await read(context))).toBe("Trusted");
      expect(spy).toHaveBeenCalledTimes(2);
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("disabled loader defaults can be re-enabled per read without mutating either runtime", async () => {
    const { asset } = await setup();
    const configured = { ...settings(), verify: { verifyTrust: false, ocspFetch: false } };
    const a = await inline.createC2pa({ wasmSrc, settings: configured });
    const b = await worker.createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href), settings: configured });
    const legacy = await createLegacy({ wasmSrc: legacyWasmSrc, settings: configured });
    clients.push(a, b, legacy);
    for (const client of [a, b, legacy]) {
      expect(await state(await client.reader.fromBlob("image/jpeg", asset))).toBe("Valid");
      expect(await state(await client.reader.fromBlob("image/jpeg", asset, { verify: { verifyTrust: true } }))).toBe("Trusted");
      expect(await state(await client.reader.fromBlob("image/jpeg", asset))).toBe("Valid");
      expect(await state(await client.reader.fromBlob("image/jpeg", asset, { trust: { verifyTrustList: false },
        verify: { verifyTrust: true } }))).toBe("Valid");
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("loader defaults and deep per-read overrides match legacy factories without affecting static Contexts", async () => {
    const { a, b, legacy, asset } = await setup();
    for (const client of [a, b, legacy]) {
      expect(await state(await client.reader.fromBlob("image/jpeg", asset))).toBe("Trusted");
      expect(await state(await client.reader.fromBlob("image/jpeg", asset, { trust: { trustAnchors: "" } }))).toBe("Valid");
      expect(await state(await client.reader.fromBlob("image/jpeg", asset, { verify: { ocspFetch: false } }))).toBe("Trusted");
    }
    expect(await state(await inline.Reader.fromBlob(a, "image/jpeg", asset))).toBe("Valid");
    expect(await state(await worker.Reader.fromBlob(b, "image/jpeg", asset))).toBe("Valid");
    expect(await state(await LegacyReader.fromBlob(legacy, "image/jpeg", asset))).toBe("Valid");
    expect(await state(await inline.Reader.fromBlob(a, "image/jpeg", asset, new inline.Context(settings())))).toBe("Trusted");
    expect(await state(await worker.Reader.fromBlob(b, "image/jpeg", asset, new worker.Context(settings())))).toBe("Trusted");
    expect(await state(await LegacyReader.fromBlob(legacy, "image/jpeg", asset, new LegacyContext(settings())))).toBe("Trusted");
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("runtime defaults are snapshotted and isolated while unsupported builder inheritance rejects", async () => {
    const { a, b, plain, configured, asset } = await setup();
    configured.trust.trustAnchors = "";
    for (const client of [a, b]) {
      expect(await state(await client.reader.fromBlob("image/jpeg", asset))).toBe("Trusted");
      expect(await state(await client.reader.fromBlob("image/jpeg", asset, { verify: { verifyTrust: false } })))
        .toBe("Valid");
      await expect(client.builder.fromDefinition(fixtures.definition)).rejects.toThrow(/Builder factory settings/);
      expect(client.liveResources).toBe(0);
    }
    expect(await state(await plain.reader.fromBlob("image/jpeg", asset))).toBe("Valid");
    const staticBuilders = await Promise.all([
      inline.Builder.fromDefinition(a, fixtures.definition), worker.Builder.fromDefinition(b, fixtures.definition),
    ]);
    for (const builder of staticBuilders) await builder.free();
  });
  test("unsupported loader settings and OCSP without an authorized per-read host fail explicitly and allow retry", async () => {
    await expect(inline.createC2pa({ wasmSrc, settings: { verify: { remoteManifestFetch: true } } })).rejects.toThrow(/Unsupported reader setting/);
    await expect(worker.createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href),
      settings: { verify: { remoteManifestFetch: true } } })).rejects.toThrow(/Unsupported reader setting/);
    const { asset } = await setup();
    const a = await inline.createC2pa({ wasmSrc, settings: { verify: { ocspFetch: true } } });
    const b = await worker.createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href),
      settings: { verify: { ocspFetch: true } } });
    clients.push(a, b);
    for (const client of [a, b]) {
      await expect(client.reader.fromBlob("image/jpeg", asset)).rejects.toThrow(/Unsupported reader setting/);
      expect(client.liveResources).toBe(0);
      expect(await state(await client.reader.fromBlob("image/jpeg", asset, { verify: { ocspFetch: false } }))).toBe("Valid");
    }
  });
  test("inherited online OCSP uses only the explicitly authorized operation host in inline and Worker factories", async () => {
    vi.restoreAllMocks();
    const response = await fetch("/__m3/ocsp/fixtures");
    expect(response.ok).toBe(true);
    const fixture = await response.json() as {
      now: number; origin: string; certs: Record<string, string>; root: string; rootDer: string; key: string;
    };
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, fixture.now - Date.now())));
    const defaults = { trust: { trustAnchors: fixture.root }, verify: { verifyTrust: true, ocspFetch: true } };
    const a = await inline.createC2pa({ wasmSrc, settings: defaults });
    const b = await worker.createC2pa({ wasmSrc, workerSrc: new URL(unclockedWorkerSrc, location.href), settings: defaults });
    clients.push(a, b);
    const key = await crypto.subtle.importKey("pkcs8", bytes(fixture.key.replace(/-----[^-]+-----|\s/g, "")),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const builder = await inline.Builder.fromDefinition(a, fixtures.definition);
    const result = await builder.sign({
      alg: "es256", certs: [bytes(fixture.certs.good), bytes(fixture.rootDer)], async sign(data) {
        return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
      },
    }, "image/jpeg", new Blob([bytes(fixtures.source)]));
    await builder.free();
    const asset = new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" });
    for (const client of [a, b]) {
      await expect(client.reader.fromBlob("image/jpeg", asset)).rejects.toThrow(/Unsupported reader setting/);
      const reader = await client.reader.fromBlob("image/jpeg", asset, undefined, undefined, undefined,
        { allowedOrigins: [fixture.origin], maxBytes: 64 * 1024, timeoutMs: 2000 });
      try {
        const report = await reader!.json();
        expect(report.validation_state).toBe("Trusted");
        expect(report.validation_results.activeManifest.success)
          .toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.notRevoked" }));
      } finally { await reader!.free() }
      expect(client.liveResources).toBe(0);
    }
  });
});
