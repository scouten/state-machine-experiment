import { afterEach, describe, expect, test } from "vitest";
import * as inline from "c2pa-js-state-machine/inline";
import * as worker from "c2pa-js-state-machine/worker";
import { createC2pa as createLegacy, Reader as LegacyReader } from "@contentauth/c2pa-web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import workerSrc from "./clocked-worker.ts?worker&url";
import assetUrl from "../.cache/upstream/packages/c2pa-web/test/assets/C_with_CAWG_data.jpg?url";
import thumbnailUrl from "../.cache/upstream/packages/c2pa-web/test/assets/C_with_CAWG_data_thumbnail.jpg?url";
import claimRoot from "test/trust/anchor-correct.pem?raw";
import identityRoot from "test/trust/anchor-cawg.pem?raw";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };
import iconAssetUrl from "./fixtures/generator-icons-v2.jpg?url";
import databoxIconAssetUrl from "./fixtures/generator-icons-v1.jpg?url";
import iconSource from "./fixtures/generator-icon.svg?raw";
import ingredientAssetUrl from "./fixtures/ingredient-thumbnails-v2.jpg?url";
import ingredientDataboxUrl from "./fixtures/ingredient-thumbnails-v1.jpg?url";
import ingredientDataUrl from "./fixtures/ingredient-data-v2.jpg?url";
import ingredientDataDataboxUrl from "./fixtures/ingredient-data-v1.jpg?url";
import dataSource from "./fixtures/ingredient-data.json?raw";

const clients: { dispose(): void }[] = [];
async function setup() {
  const a = await inline.createC2pa({ wasmSrc });
  const b = await worker.createC2pa({ wasmSrc, workerSrc: new URL(workerSrc, location.href) });
  const legacy = await createLegacy({ wasmSrc: legacyWasmSrc });
  clients.push(a, b, legacy);
  const blob = new Blob([await (await fetch(assetUrl)).arrayBuffer()], { type: "image/jpeg" });
  const readers = [
    await inline.Reader.fromBlob(a, blob.type, blob),
    await worker.Reader.fromBlob(b, blob.type, blob),
    await LegacyReader.fromBlob(legacy, blob.type, blob),
  ];
  expect(readers.every(Boolean)).toBe(true);
  return { a, b, legacy, readers, blob };
}
function thumbnail(value: unknown): { format: string; identifier: string } {
  return resourceRef(value, "thumbnail");
}
function resourceRef(value: unknown, field: "thumbnail" | "data"): { format: string; identifier: string } {
  if (!value || typeof value !== "object" || !(field in value)) throw new Error(`Missing ${field}`);
  const ref: unknown = Reflect.get(value, field);
  if (!ref || typeof ref !== "object" || !("format" in ref) || typeof ref.format !== "string" ||
      !("identifier" in ref) || typeof ref.identifier !== "string") throw new Error("Invalid thumbnail");
  return { format: ref.format, identifier: ref.identifier };
}
function numericAssertion(manifest: unknown): unknown {
  if (!manifest || typeof manifest !== "object" || !("assertions" in manifest) ||
      !Array.isArray(manifest.assertions)) throw new Error("Missing assertions");
  const assertion: unknown = manifest.assertions.find((item: unknown) =>
    item && typeof item === "object" && "label" in item && item.label === "test.numeric");
  if (!assertion || typeof assertion !== "object" || !("data" in assertion))
    throw new Error("Missing numeric assertion");
  return assertion.data;
}
function ingredients(manifest: unknown): unknown[] {
  if (!manifest || typeof manifest !== "object" || !("ingredients" in manifest) ||
      !Array.isArray(manifest.ingredients)) throw new Error("Missing ingredient report");
  if (!("assertions" in manifest) || !Array.isArray(manifest.assertions)) throw new Error("Missing assertions");
  expect(manifest.assertions.some((assertion: unknown) => assertion && typeof assertion === "object" &&
    "label" in assertion && typeof assertion.label === "string" &&
    assertion.label.startsWith("c2pa.ingredient"))).toBe(false);
  return manifest.ingredients;
}
function generatorIcon(manifest: unknown): { format: string; identifier: string } {
  if (!manifest || typeof manifest !== "object" || !("claim_generator_info" in manifest) ||
      !Array.isArray(manifest.claim_generator_info)) throw new Error("Missing generators");
  const info: unknown = manifest.claim_generator_info[0];
  if (!info || typeof info !== "object" || !("icon" in info)) throw new Error("Missing generator icon");
  const icon = info.icon;
  if (!icon || typeof icon !== "object" || !("format" in icon) || typeof icon.format !== "string" ||
      !("identifier" in icon) || typeof icon.identifier !== "string") throw new Error("Invalid generator icon");
  return { format: icon.format, identifier: icon.identifier };
}
async function signedAssertions(runtime: inline.Runtime, assertions: { label: string; data: unknown; created?: boolean }[]) {
  const decode = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", decode(fixtures.key.replace(/-----[^-]+-----|\s/g, "")),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const builder = await inline.Builder.fromDefinition(runtime, {
    ...fixtures.definition, assertions: [...fixtures.definition.assertions, ...assertions],
  });
  try {
    const output = await builder.sign({
      alg: "es256", certs: [decode(fixtures.cert)],
      async sign(bytes) {
        return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(bytes)));
      },
    }, "image/jpeg", new Blob([decode(fixtures.source)], { type: "image/jpeg" }));
    return new Blob([new Uint8Array(output.asset)], { type: "image/jpeg" });
  } finally { await builder.free() }
}
describe("M3 embedded resources", () => {
  afterEach(() => { for (const client of clients.splice(0)) client.dispose() });
  test("ingredient data resources and thumbnails coexist with exact legacy reports and owned positional bytes", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await (await fetch(ingredientDataUrl)).blob();
    const bytes = new TextEncoder().encode(dataSource);
    const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
    const settings = { trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } };
    const configured = [
      await inline.Reader.fromBlob(a, "image/jpeg", blob, new inline.Context(settings)),
      await worker.Reader.fromBlob(b, "image/jpeg", blob, new worker.Context(settings)),
      await LegacyReader.fromBlob(legacy, "image/jpeg", blob, new inline.Context(settings)),
    ];
    const expected = await configured[2]!.manifestStore();
    expect(expected.validation_state).toBe("Trusted");
    const expectedJson = await configured[2]!.json();
    const active = await configured[2]!.activeManifest();
    const inputs = ingredients(active);
    const refs = inputs.map((input) => resourceRef(input, "data"));
    expect(refs).toHaveLength(2);
    expect(new Set(refs.map((ref) => ref.identifier)).size).toBe(2);
    expect(refs[1].identifier).toContain("/c2pa.assertions/c2pa.embedded-data__1");
    const thumb = thumbnail(inputs[0]);
    for (const reader of configured) {
      expect(await reader!.manifestStore()).toEqual(expected);
      expect(await reader!.activeManifest()).toEqual(active);
      expect(await reader!.json()).toEqual(expectedJson);
      expect(await reader!.resourceToBytes(thumb.identifier)).toEqual(new TextEncoder().encode(iconSource));
      for (const ref of refs) {
        expect(ref.format).toBe("application/json");
        const first = await reader!.resourceToBytes(ref.identifier);
        expect(first).toEqual(bytes);
        first.fill(0);
        expect(await reader!.resourceToBytes(ref.identifier)).toEqual(bytes);
      }
      if (reader !== configured[2]) {
        await expect(reader!.resourceToBytes(refs[1].identifier + "__missing")).rejects.toThrow(/ResourceNotFound/);
        expect(await reader!.resourceToBytes(refs[1].identifier)).toEqual(bytes);
      }
      await reader!.free();
    }
    for (const reader of configured.slice(0, 2))
      await expect(reader!.resourceToBytes(refs[0].identifier)).rejects.toThrow(/freed/i);
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("tampered ingredient data is never trusted and leaves other data and thumbnails unchanged", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const bytes = new Uint8Array(await (await fetch(ingredientDataUrl)).arrayBuffer());
    const expected = new TextEncoder().encode(dataSource);
    const marker = new TextEncoder().encode("M3_INGREDIENT_DATA_EXACT_BYTES");
    const at = bytes.findIndex((_, at) => marker.every((byte, offset) => bytes[at + offset] === byte));
    const resourceAt = expected.findIndex((_, at) => marker.every((byte, offset) => expected[at + offset] === byte));
    expect(at).toBeGreaterThan(0);
    expect(resourceAt).toBeGreaterThan(0);
    bytes[at] ^= 1;
    expected[resourceAt] ^= 1;
    const blob = new Blob([bytes], { type: "image/jpeg" });
    for (const reader of [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
      await LegacyReader.fromBlob(legacy, blob.type, blob),
    ]) {
      const store = await reader!.manifestStore();
      const inputs = ingredients(await reader!.activeManifest());
      const refs = inputs.map((input) => resourceRef(input, "data"));
      expect(store.validation_state).toBe("Invalid");
      expect(store.validation_status).toEqual(expect.arrayContaining([expect.objectContaining({
        code: "assertion.hashedURI.mismatch", url: refs[0].identifier,
      })]));
      expect(await reader!.resourceToBytes(refs[0].identifier)).toEqual(expected);
      expect(await reader!.resourceToBytes(refs[1].identifier)).toEqual(new TextEncoder().encode(dataSource));
      expect(await reader!.resourceToBytes(thumbnail(inputs[0]).identifier)).toEqual(new TextEncoder().encode(iconSource));
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("ingredient databox data rejects explicitly and later embedded data reads recover", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await (await fetch(ingredientDataDataboxUrl)).blob();
    const oldReader = await LegacyReader.fromBlob(legacy, "image/jpeg", blob);
    expect(resourceRef(ingredients(await oldReader!.activeManifest())[1], "data").identifier).toContain("/c2pa.databoxes/");
    await oldReader!.free();
    for (const reader of [
      await inline.Reader.fromBlob(a, "image/jpeg", blob),
      await worker.Reader.fromBlob(b, "image/jpeg", blob),
    ]) {
      for (const report of [() => reader!.activeManifest(), () => reader!.manifestStore(), () => reader!.json()])
        await expect(report()).rejects.toThrow(/ingredient data.*same-manifest embedded assertion/);
      await reader!.free();
      await expect(reader!.activeManifest()).rejects.toThrow(/freed/i);
    }
    const modern = await (await fetch(ingredientDataUrl)).blob();
    for (const reader of [
      await inline.Reader.fromBlob(a, "image/jpeg", modern),
      await worker.Reader.fromBlob(b, "image/jpeg", modern),
    ]) {
      expect(ingredients(await reader!.activeManifest()).map((input) => resourceRef(input, "data"))).toHaveLength(2);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("ingredient thumbnails match complete legacy stores and exact positional resource bytes", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await (await fetch(ingredientAssetUrl)).blob();
    const bytes = new TextEncoder().encode(iconSource);
    const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
    const settings = { trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } };
    const configured = [
      await inline.Reader.fromBlob(a, "image/jpeg", blob, new inline.Context(settings)),
      await worker.Reader.fromBlob(b, "image/jpeg", blob, new worker.Context(settings)),
      await LegacyReader.fromBlob(legacy, "image/jpeg", blob, new inline.Context(settings)),
    ];
    const expected = await configured[2]!.manifestStore();
    expect(expected.validation_state).toBe("Trusted");
    const expectedJson = await configured[2]!.json();
    const active = await configured[2]!.activeManifest();
    const refs = ingredients(active).map(thumbnail);
    expect(refs).toHaveLength(2);
    expect(new Set(refs.map((ref) => ref.identifier)).size).toBe(2);
    expect(refs[1].identifier).toContain("/c2pa.assertions/c2pa.thumbnail.ingredient__1");
    for (const reader of configured) {
      expect(await reader!.manifestStore()).toEqual(expected);
      expect(await reader!.activeManifest()).toEqual(active);
      expect(await reader!.json()).toEqual(expectedJson);
      for (const ref of refs) {
        expect(ref.format).toBe("image/svg+xml");
        const first = await reader!.resourceToBytes(ref.identifier);
        expect(first).toEqual(bytes);
        first.fill(0);
        expect(await reader!.resourceToBytes(ref.identifier)).toEqual(bytes);
      }
      if (reader !== configured[2]) {
        await expect(reader!.resourceToBytes(refs[1].identifier + "__missing")).rejects.toThrow(/ResourceNotFound/);
        expect(await reader!.resourceToBytes(refs[1].identifier)).toEqual(bytes);
      }
      await reader!.free();
    }
    for (const reader of configured.slice(0, 2))
      await expect(reader!.resourceToBytes(refs[0].identifier)).rejects.toThrow(/freed/i);
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("tampered ingredient thumbnails retain live hash failures and exact changed bytes", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const bytes = new Uint8Array(await (await fetch(ingredientAssetUrl)).arrayBuffer());
    const expected = new TextEncoder().encode(iconSource);
    const marker = new TextEncoder().encode("M3_GENERATOR_ICON_EXACT_BYTES");
    const at = bytes.findIndex((_, at) => marker.every((byte, offset) => bytes[at + offset] === byte));
    const resourceAt = expected.findIndex((_, at) => marker.every((byte, offset) => expected[at + offset] === byte));
    expect(at).toBeGreaterThan(0);
    expect(resourceAt).toBeGreaterThan(0);
    bytes[at] ^= 1;
    expected[resourceAt] ^= 1;
    const blob = new Blob([bytes], { type: "image/jpeg" });
    for (const reader of [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
      await LegacyReader.fromBlob(legacy, blob.type, blob),
    ]) {
      const store = await reader!.manifestStore();
      const refs = ingredients(await reader!.activeManifest()).map(thumbnail);
      expect(store.validation_state).toBe("Invalid");
      expect(store.validation_status).toEqual(expect.arrayContaining([expect.objectContaining({
        code: "assertion.hashedURI.mismatch", url: refs[0].identifier,
      })]));
      expect(await reader!.resourceToBytes(refs[0].identifier)).toEqual(expected);
      expect(await reader!.resourceToBytes(refs[1].identifier)).toEqual(new TextEncoder().encode(iconSource));
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("ingredient databox thumbnails reject explicitly without enabling linked histories and recover", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await (await fetch(ingredientDataboxUrl)).blob();
    const oldReader = await LegacyReader.fromBlob(legacy, "image/jpeg", blob);
    expect(thumbnail(ingredients(await oldReader!.activeManifest())[0]).identifier).toContain("/c2pa.databoxes/");
    await oldReader!.free();
    for (const reader of [
      await inline.Reader.fromBlob(a, "image/jpeg", blob),
      await worker.Reader.fromBlob(b, "image/jpeg", blob),
    ]) {
      for (const report of [() => reader!.activeManifest(), () => reader!.manifestStore(), () => reader!.json()])
        await expect(report()).rejects.toThrow(/ingredient thumbnail.*same-manifest embedded assertion/);
      await reader!.free();
      await expect(reader!.activeManifest()).rejects.toThrow(/freed/i);
    }
    const modern = await (await fetch(ingredientAssetUrl)).blob();
    for (const reader of [
      await inline.Reader.fromBlob(a, "image/jpeg", modern),
      await worker.Reader.fromBlob(b, "image/jpeg", modern),
    ]) {
      expect(ingredients(await reader!.activeManifest()).map(thumbnail)).toHaveLength(2);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("real c2pa-rs generator icons match complete legacy reports and exact owned resource bytes", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await (await fetch(iconAssetUrl)).blob();
    const bytes = new TextEncoder().encode(iconSource);
    const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
    const settings = { trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } };
    const configured = [
      await inline.Reader.fromBlob(a, "image/jpeg", blob, new inline.Context(settings)),
      await worker.Reader.fromBlob(b, "image/jpeg", blob, new worker.Context(settings)),
      await LegacyReader.fromBlob(legacy, "image/jpeg", blob, new inline.Context(settings)),
    ];
    const expected = await configured[2]!.manifestStore();
    expect(expected.validation_state).toBe("Trusted");
    const expectedJson = await configured[2]!.json();
    const active = await configured[2]!.activeManifest();
    const ref = generatorIcon(active);
    expect(ref.format).toBe("image/svg+xml");
    expect(ref.identifier).toBe(`self#jumbf=/c2pa/${expected.active_manifest}/c2pa.assertions/c2pa.icon`);
    for (const reader of configured) {
      expect(await reader!.manifestStore()).toEqual(expected);
      expect(await reader!.activeManifest()).toEqual(active);
      expect(await reader!.json()).toEqual(expectedJson);
      const first = await reader!.resourceToBytes(ref.identifier);
      expect(first).toEqual(bytes);
      first.fill(0);
      expect(await reader!.resourceToBytes(ref.identifier)).toEqual(bytes);
      if (reader !== configured[2])
        await expect(reader!.resourceToBytes(ref.identifier + "__missing")).rejects.toThrow(/ResourceNotFound/);
      expect(await reader!.resourceToBytes(ref.identifier)).toEqual(bytes);
      await reader!.free();
    }
    for (const reader of configured.slice(0, 2))
      await expect(reader!.resourceToBytes(ref.identifier)).rejects.toThrow(/freed/i);
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("tampered generator icon bytes remain extractable but never cancel hashed-URI failure", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const bytes = new Uint8Array(await (await fetch(iconAssetUrl)).arrayBuffer());
    const expected = new TextEncoder().encode(iconSource);
    const marker = new TextEncoder().encode("M3_GENERATOR_ICON_EXACT_BYTES");
    const at = bytes.findIndex((_, at) => marker.every((byte, offset) => bytes[at + offset] === byte));
    const iconAt = expected.findIndex((_, at) => marker.every((byte, offset) => expected[at + offset] === byte));
    expect(at).toBeGreaterThan(0);
    expect(iconAt).toBeGreaterThan(0);
    bytes[at] ^= 1;
    expected[iconAt] ^= 1;
    const blob = new Blob([bytes], { type: "image/jpeg" });
    for (const reader of [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
      await LegacyReader.fromBlob(legacy, blob.type, blob),
    ]) {
      const store = await reader!.manifestStore();
      const ref = generatorIcon(await reader!.activeManifest());
      expect(store.validation_state).toBe("Invalid");
      expect(store.validation_status).toEqual(expect.arrayContaining([expect.objectContaining({
        code: "assertion.hashedURI.mismatch", url: ref.identifier,
      })]));
      expect(await reader!.resourceToBytes(ref.identifier)).toEqual(expected);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("legacy databox icons fail reporting explicitly and later modern reads still work", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await (await fetch(databoxIconAssetUrl)).blob();
    const oldReader = await LegacyReader.fromBlob(legacy, "image/jpeg", blob);
    const ref = generatorIcon(await oldReader!.activeManifest());
    expect(ref.identifier).toContain("/c2pa.databoxes/");
    expect((await oldReader!.resourceToBytes(ref.identifier)).length).toBeGreaterThan(0);
    await oldReader!.free();
    for (const reader of [
      await inline.Reader.fromBlob(a, "image/jpeg", blob),
      await worker.Reader.fromBlob(b, "image/jpeg", blob),
    ]) {
      for (const report of [() => reader!.activeManifest(), () => reader!.manifestStore(), () => reader!.json()])
        await expect(report()).rejects.toThrow(/generator icon.*same-manifest embedded assertion/);
      await expect(reader!.resourceToBytes(ref.identifier)).rejects.toThrow(/ResourceNotFound/);
      await reader!.free();
    }
    const modern = await (await fetch(iconAssetUrl)).blob();
    for (const reader of [
      await inline.Reader.fromBlob(a, "image/jpeg", modern),
      await worker.Reader.fromBlob(b, "image/jpeg", modern),
    ]) {
      expect(generatorIcon(await reader!.activeManifest()).format).toBe("image/svg+xml");
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  async function checkTrust(verifyTrust: boolean, verifyTrustList: boolean) {
    const { a, b, legacy, readers, blob } = await setup();
    for (const reader of readers) await reader!.free();
    const settings = {
      trust: { trustAnchors: claimRoot },
      cawgTrust: { trustAnchors: identityRoot, verifyTrustList },
      verify: { verifyTrust, ocspFetch: false },
    };
    const configured = [
      await inline.Reader.fromBlob(a, blob.type, blob, new inline.Context(settings)),
      await worker.Reader.fromBlob(b, blob.type, blob, new worker.Context(settings)),
      await LegacyReader.fromBlob(legacy, blob.type, blob, new inline.Context(settings)),
    ];
    const expected = await configured[2]!.manifestStore();
    for (const reader of configured) {
      const store = await reader!.manifestStore();
      expect(store).toEqual(expected);
      expect(await reader!.json()).toEqual(await configured[2]!.json());
      expect(store.validation_state).toBe(verifyTrust && verifyTrustList ? "Trusted" : "Valid");
      const codes = Object.values(store.validation_results!.activeManifest!).flat().map((status: unknown) => {
        if (!status || typeof status !== "object" || !("code" in status) || typeof status.code !== "string")
          throw new Error("Missing validation status code");
        return status.code;
      });
      expect(codes.includes("signingCredential.trusted")).toBe(verifyTrust);
      expect(codes.includes("signingCredential.untrusted")).toBe(false);
      expect(codes.includes("cawg.x509.credential.trusted")).toBe(verifyTrustList);
      expect(codes.includes("cawg.x509.credential.untrusted")).toBe(!verifyTrustList);
    }
    for (const reader of configured) await reader!.free();
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  }
  test("disabled claim trust and disabled CAWG list match complete legacy reports", () => checkTrust(false, false));
  test("disabled claim trust retains independent trusted CAWG reports", () => checkTrust(false, true));
  test("trusted claim with disabled CAWG list matches legacy Valid reporting", () => checkTrust(true, false));
  test("enabled claim trust and CAWG list match complete legacy reports", () => checkTrust(true, true));
  test("claim thumbnail metadata and exact bytes match legacy on inline and Worker", async () => {
    const { readers } = await setup();
    const expected = new Uint8Array(await (await fetch(thumbnailUrl)).arrayBuffer());
    const refs = [];
    for (const reader of readers) {
      const ref = thumbnail(await reader!.activeManifest());
      refs.push(ref);
      const store = await reader!.manifestStore();
      expect(thumbnail(store.manifests![store.active_manifest!])).toEqual(ref);
      expect(thumbnail((await reader!.json()).manifests![store.active_manifest!])).toEqual(ref);
      expect(await reader!.resourceToBytes(ref.identifier)).toEqual(expected);
      await reader!.free();
    }
    expect(refs[0]).toEqual(refs[2]);
    expect(refs[1]).toEqual(refs[2]);
    expect(refs[0].format).toBe("image/jpeg");
  });
  test("exact active manifest matches legacy and remains identical in object reporting surfaces", async () => {
    const { readers } = await setup();
    const expected = await readers[2]!.activeManifest();
    for (const reader of readers.slice(0, 2)) {
      const active = await reader!.activeManifest();
      expect(active).toEqual(expected);
      const store = await reader!.manifestStore();
      expect(store.manifests![store.active_manifest!]).toEqual(active);
      await reader!.free();
    }
    await readers[2]!.free();
  });
  test("complete JSON matches legacy for untrusted and independently trusted identity stores without mutating object views", async () => {
    const { a, b, legacy, readers, blob } = await setup();
    const settings = {
      trust: { trustAnchors: claimRoot },
      cawgTrust: { trustAnchors: identityRoot },
      verify: { verifyTrust: true, ocspFetch: false },
    };
    const trusted = [
      await inline.Reader.fromBlob(a, blob.type, blob, new inline.Context(settings)),
      await worker.Reader.fromBlob(b, blob.type, blob, new worker.Context(settings)),
      await LegacyReader.fromBlob(legacy, blob.type, blob, new inline.Context(settings)),
    ];
    for (const group of [readers, trusted]) {
      const expected = await group[2]!.json();
      const expectedStore = await group[2]!.manifestStore();
      expect(expected).not.toEqual(expectedStore);
      for (const reader of group.slice(0, 2)) {
        const before = await reader!.manifestStore();
        expect(await reader!.json()).toEqual(expected);
        expect(await reader!.json()).toEqual(expected);
        expect(await reader!.manifestStore()).toEqual(before);
        expect(before).toEqual(expectedStore);
        expect(await reader!.activeManifest()).toEqual(before.manifests![before.active_manifest!]);
        await reader!.free();
        await expect(reader!.json()).rejects.toThrow(/freed/i);
      }
      await group[2]!.free();
    }
  });
  test("JSON reproduces legacy numeric-array formatting beyond hash fields while object arrays remain unchanged", async () => {
    const { a, b, legacy, readers } = await setup();
    const data = {
      hash: [0, 1, 254, 255],
      not_a_hash: [256, 257, -1, 1.5],
      no_unsigned: [-1, 0.5],
      empty: [],
      mixed: [1, "two", null, { nested: [3, 4] }],
      nested: [[1, 2], { bytes: [5] }],
    };
    const blob = await signedAssertions(a, [{ label: "test.numeric", data }]);
    const signed = [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
      await LegacyReader.fromBlob(legacy, blob.type, blob),
    ];
    const expectedJson = {
      hash: "AAH+/w==", not_a_hash: "AAE=", no_unsigned: "", empty: [],
      mixed: [1, "two", null, { nested: "AwQ=" }], nested: [[1, 2], { bytes: "BQ==" }],
    };
    const expectedObject = { ...data, mixed: [1, "two", undefined, { nested: [3, 4] }] };
    for (const reader of signed) {
      expect(numericAssertion(await reader!.activeManifest())).toEqual(expectedObject);
      const json = await reader!.json();
      expect(numericAssertion(json.manifests![json.active_manifest!])).toEqual(expectedJson);
      const store = await reader!.manifestStore();
      expect(numericAssertion(store.manifests![store.active_manifest!])).toEqual(expectedObject);
      await reader!.free();
    }
    for (const reader of readers) await reader!.free();
  });
  test("resource-free v1 v2 and positional v3 ingredient metadata matches legacy object and JSON reports", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await signedAssertions(a, [
      { label: "c2pa.ingredient", created: false, data: {
        "dc:title": "Original \u00e9.jpg", "dc:format": "image/jpeg", instanceID: "xmp.iid:original",
        documentID: "xmp.did:original", relationship: "parentOf",
      } },
      { label: "c2pa.ingredient.v2", created: false, data: {
        "dc:title": "Dataset", "dc:format": "application/json", relationship: "componentOf",
        description: "Input metadata", informational_URI: "https://example.invalid/dataset",
        data_types: [{ type: "dataset", version: "1.0" }],
      } },
      { label: "c2pa.ingredient.v3", created: false, data: {
        "dc:title": "Capture", "dc:format": "image/jpeg", instanceID: "xmp.iid:capture",
        relationship: "inputTo", description: "Camera input",
        informationalURI: "https://example.invalid/capture",
        digitalSourceType: "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
        dataTypes: [{ type: "example.custom" }],
      } },
      { label: "c2pa.ingredient.v3__1", created: false, data: { relationship: "componentOf" } },
      { label: "test.ingredient", data: { relationship: "componentOf" } },
    ]);
    const configured = [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
      await LegacyReader.fromBlob(legacy, blob.type, blob),
    ];
    const expected = await configured[2]!.manifestStore();
    const expectedActive = await configured[2]!.activeManifest();
    const expectedJson = await configured[2]!.json();
    expect(ingredients(expectedActive)).toHaveLength(4);
    expect(ingredients(expectedActive)[0]).toMatchObject({ title: "Original \u00e9.jpg",
      relationship: "parentOf", instance_id: "xmp.iid:original", document_id: "xmp.did:original" });
    expect(ingredients(expectedActive)[2]).toMatchObject({ informational_URI: "https://example.invalid/capture",
      data_types: [{ type: "example.custom" }] });
    for (const reader of configured) {
      expect(await reader!.manifestStore()).toEqual(expected);
      expect(await reader!.activeManifest()).toEqual(expectedActive);
      expect(await reader!.json()).toEqual(expectedJson);
      expect(ingredients((await reader!.manifestStore()).manifests![expected.active_manifest!])).toHaveLength(4);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("ingredient review ratings creation time and custom metadata match legacy across all versions", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const metadata = {
      dateTime: "2026-10-14T10:20:30Z",
      reviewRatings: [
        { explanation: "A signed opinion, not validation", code: "ingredient.modified", value: 5, ignored: true },
        { explanation: "Lower encoding boundary", code: null, value: 0 },
        { explanation: "Upper encoding boundary", value: 255 },
      ],
      "org.example.review": { author: "Reviewer \u00e9", scores: [1, 2, 255] },
    };
    const blob = await signedAssertions(a, [
      { label: "c2pa.ingredient", created: false, data: {
        "dc:title": "Original", "dc:format": "image/jpeg", instanceID: "xmp.iid:original",
        relationship: "parentOf", metadata,
      } },
      { label: "c2pa.ingredient.v2", created: false, data: {
        "dc:title": "Component", "dc:format": "image/jpeg", relationship: "componentOf", metadata,
      } },
      { label: "c2pa.ingredient.v3", created: false, data: { relationship: "inputTo", metadata } },
      { label: "c2pa.ingredient.v3__1", created: false, data: { relationship: "inputTo",
        metadata: { dateTime: null, reviewRatings: null, reference: null } } },
    ]);
    const configured = [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
      await LegacyReader.fromBlob(legacy, blob.type, blob),
    ];
    const expected = await configured[2]!.manifestStore();
    const expectedActive = await configured[2]!.activeManifest();
    const expectedJson = await configured[2]!.json();
    const expectedMetadata = {
      ...metadata, reviewRatings: metadata.reviewRatings.map(({ explanation, value, code }) =>
        code == null ? { explanation, value } : { explanation, value, code }),
    };
    expect(ingredients(expectedActive)).toHaveLength(4);
    expect(ingredients(expectedActive).slice(0, 3)).toEqual([
      expect.objectContaining({ metadata: expectedMetadata }),
      expect.objectContaining({ metadata: expectedMetadata }),
      expect.objectContaining({ metadata: expectedMetadata }),
    ]);
    expect(ingredients(expectedActive)[3]).toMatchObject({ metadata: {} });
    for (const reader of configured) {
      expect(await reader!.manifestStore()).toEqual(expected);
      expect(await reader!.activeManifest()).toEqual(expectedActive);
      expect(await reader!.json()).toEqual(expectedJson);
      const store = await reader!.manifestStore();
      expect(store.validation_state).toBe("Valid");
      expect(store.validation_status?.some((status) => status.code === "ingredient.modified")).toBe(false);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("unsupported ingredient metadata references fail explicitly and a later Worker read succeeds", async () => {
    const { a, b, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await signedAssertions(a, [{ label: "c2pa.ingredient.v3", created: false, data: {
      relationship: "componentOf", metadata: {
        reference: { url: "self#jumbf=c2pa.assertions/missing", hash: [1] },
      },
    } }]);
    for (const reader of [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
    ]) {
      await expect(reader!.activeManifest()).rejects.toThrow(/metadata: reference reporting is not yet supported/);
      await expect(reader!.manifestStore()).rejects.toThrow(/metadata: reference reporting is not yet supported/);
      await expect(reader!.json()).rejects.toThrow(/metadata: reference reporting is not yet supported/);
      await reader!.free();
      await expect(reader!.activeManifest()).rejects.toThrow(/freed/i);
    }
    const valid = await signedAssertions(a, [{ label: "c2pa.ingredient.v3", created: false, data: {
      relationship: "inputTo", metadata: { reviewRatings: [] },
    } }]);
    const reader = await worker.Reader.fromBlob(b, valid.type, valid);
    expect(ingredients(await reader!.activeManifest())[0]).toMatchObject({ metadata: { reviewRatings: [] } });
    await reader!.free();
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("malformed ingredient review ratings reject rather than silently disappearing", async () => {
    const { a, b, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await signedAssertions(a, [{ label: "c2pa.ingredient.v3", created: false, data: {
      relationship: "componentOf", metadata: { reviewRatings: [{ explanation: "Overflow", value: 256 }] },
    } }]);
    for (const reader of [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
    ]) {
      await expect(reader!.activeManifest()).rejects.toThrow(/review value must be an unsigned byte/);
      await expect(reader!.manifestStore()).rejects.toThrow(/review value must be an unsigned byte/);
      await expect(reader!.json()).rejects.toThrow(/review value must be an unsigned byte/);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("linked ingredient reporting fails explicitly without fallback and readers remain releasable", async () => {
    const { a, b, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const blob = await signedAssertions(a, [{ label: "c2pa.ingredient.v3", created: false, data: {
      relationship: "componentOf", activeManifest: { url: "self#jumbf=/c2pa/missing", hash: [1] },
    } }]);
    for (const reader of [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
    ]) {
      await expect(reader!.activeManifest()).rejects.toThrow(/activeManifest reporting is not yet supported/);
      await expect(reader!.manifestStore()).rejects.toThrow(/activeManifest reporting is not yet supported/);
      await expect(reader!.json()).rejects.toThrow(/activeManifest reporting is not yet supported/);
      await reader!.free();
      await expect(reader!.activeManifest()).rejects.toThrow(/freed/i);
    }
    const valid = await signedAssertions(a, [{ label: "c2pa.ingredient.v3", created: false,
      data: { relationship: "componentOf" } }]);
    const reader = await worker.Reader.fromBlob(b, valid.type, valid);
    expect(ingredients(await reader!.activeManifest())).toHaveLength(1);
    await reader!.free();
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("tampered ingredient metadata never cancels live integrity failures or claims source provenance", async () => {
    const { a, b, legacy, readers } = await setup();
    for (const reader of readers) await reader!.free();
    const original = await signedAssertions(a, [{ label: "c2pa.ingredient.v3", created: false, data: {
      relationship: "componentOf", metadata: {
        reviewRatings: [{ explanation: "UNIQUE_INGREDIENT_REVIEW", code: "ingredient.modified", value: 5 }],
      },
    } }]);
    const bytes = new Uint8Array(await original.arrayBuffer());
    const marker = new TextEncoder().encode("UNIQUE_INGREDIENT_REVIEW");
    const start = bytes.findIndex((_, at) => marker.every((byte, offset) => bytes[at + offset] === byte));
    expect(start).toBeGreaterThan(0);
    bytes[start] ^= 1;
    const damaged = new Blob([bytes], { type: original.type });
    for (const reader of [
      await inline.Reader.fromBlob(a, damaged.type, damaged),
      await worker.Reader.fromBlob(b, damaged.type, damaged),
      await LegacyReader.fromBlob(legacy, damaged.type, damaged),
    ]) {
      const store = await reader!.manifestStore();
      expect(store.validation_state).toBe("Invalid");
      expect(store.validation_status).toEqual(expect.arrayContaining([expect.objectContaining({
        code: "assertion.hashedURI.mismatch",
        url: `self#jumbf=/c2pa/${store.active_manifest}/c2pa.assertions/c2pa.ingredient.v3`,
      })]));
      expect(ingredients(await reader!.activeManifest())).toEqual([expect.objectContaining({
        metadata: { reviewRatings: [{
          explanation: "TNIQUE_INGREDIENT_REVIEW", code: "ingredient.modified", value: 5,
        }] },
      })]);
      await reader!.free();
    }
    expect(a.liveResources).toBe(0);
    expect(b.liveResources).toBe(0);
  });
  test("signer metadata remains the same when independent claim and identity anchors establish trust", async () => {
    const { a, b, legacy, readers, blob } = await setup();
    const expected = await readers[2]!.activeManifest();
    const settings = {
      trust: { trustAnchors: claimRoot },
      cawgTrust: { trustAnchors: identityRoot },
      verify: { verifyTrust: true, ocspFetch: false },
    };
    const trusted = [
      await inline.Reader.fromBlob(a, blob.type, blob, new inline.Context(settings)),
      await worker.Reader.fromBlob(b, blob.type, blob, new worker.Context(settings)),
    ];
    const legacyTrusted = await LegacyReader.fromBlob(legacy, blob.type, blob, new inline.Context(settings));
    const expectedStore = await legacyTrusted!.manifestStore();
    for (const reader of trusted) {
      const store = await reader!.manifestStore();
      expect(store).toEqual(expectedStore);
      expect(store.validation_state).toBe("Trusted");
      expect(store.validation_results.activeManifest.success).toContainEqual(expect.objectContaining({ code: "cawg.x509.credential.trusted" }));
      expect(await reader!.activeManifest()).toEqual(expected);
      await reader!.free();
    }
    await legacyTrusted!.free();
    for (const reader of readers) await reader!.free();
  });
  test("complete untrusted stores match legacy and summarize only claim and identity trust failures", async () => {
    const { readers } = await setup();
    const expected = await readers[2]!.manifestStore();
    for (const reader of readers.slice(0, 2)) {
      const store = await reader!.manifestStore();
      expect(store).toEqual(expected);
      expect(store.validation_state).toBe("Valid");
      expect(store.validation_status?.map((status) => status.code)).toEqual([
        "signingCredential.untrusted", "cawg.x509.credential.untrusted",
      ]);
      expect(store.validation_results?.activeManifest?.failure).toEqual(store.validation_status);
      await reader!.free();
    }
    await readers[2]!.free();
  });
  test("tampered resource failure remains visible in the full report while unrelated successes are retained", async () => {
    const { a, b, readers, blob } = await setup();
    const asset = new Uint8Array(await blob.arrayBuffer());
    const thumbnail = new Uint8Array(await (await fetch(thumbnailUrl)).arrayBuffer());
    const start = asset.findIndex((_, at) => thumbnail.every((byte, offset) => asset[at + offset] === byte));
    expect(start).toBeGreaterThan(0);
    asset[start + 100] ^= 1;
    const damaged = new Blob([asset], { type: blob.type });
    const invalid = [
      await inline.Reader.fromBlob(a, blob.type, damaged),
      await worker.Reader.fromBlob(b, blob.type, damaged),
      await inline.Reader.fromBlob(a, blob.type, damaged, new inline.Context({ verify: { verifyTrust: false } })),
      await worker.Reader.fromBlob(b, blob.type, damaged, new worker.Context({ verify: { verifyTrust: false } })),
    ];
    for (const reader of invalid) {
      const store = await reader!.manifestStore();
      expect(store.validation_state).toBe("Invalid");
      const mismatch = store.validation_results.activeManifest.failure.filter(
        (status) => status.code === "assertion.hashedURI.mismatch");
      expect(mismatch).toHaveLength(1);
      expect(mismatch[0].url).toBe(`self#jumbf=/c2pa/${store.active_manifest}/c2pa.assertions/c2pa.thumbnail.claim`);
      expect(store.validation_status).toContainEqual(mismatch[0]);
      expect(store.validation_status?.some((status) => status.code === "claimSignature.validated")).toBe(false);
      expect(store.validation_results.activeManifest.success)
        .toContainEqual(expect.objectContaining({ code: "claimSignature.validated" }));
      await reader!.free();
    }
    for (const reader of readers) await reader!.free();
  });
  test("resource results are independent copies and unknown identifiers fail without poisoning the reader", async () => {
    const { readers } = await setup();
    for (const reader of readers) {
      const ref = thumbnail(await reader!.activeManifest());
      const original = await reader!.resourceToBytes(ref.identifier);
      const copy = await reader!.resourceToBytes(ref.identifier);
      expect(copy).toEqual(original);
      copy.fill(0);
      expect(await reader!.resourceToBytes(ref.identifier)).toEqual(original);
      await expect(reader!.resourceToBytes("self#jumbf=/c2pa/missing/c2pa.assertions/c2pa.thumbnail.claim")).rejects.toBeDefined();
      expect(await reader!.resourceToBytes(ref.identifier)).toEqual(original);
      await reader!.free();
    }
  });
  test("resource lookup rejects noncanonical identifiers and respects free and dispose", async () => {
    const { a, b, readers } = await setup();
    for (const reader of readers.slice(0, 2)) {
      const ref = thumbnail(await reader!.activeManifest());
      for (const uri of ["c2pa.thumbnail.claim", "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim",
        "https://example.invalid/thumbnail.jpg", `${ref.identifier}/extra`]) {
        await expect(reader!.resourceToBytes(uri)).rejects.toThrow("ResourceNotFound");
      }
      await reader!.free();
      await expect(reader!.resourceToBytes(ref.identifier)).rejects.toThrow("freed");
    }
    const blob = new Blob([await (await fetch(assetUrl)).arrayBuffer()], { type: "image/jpeg" });
    const remaining = [
      await inline.Reader.fromBlob(a, blob.type, blob),
      await worker.Reader.fromBlob(b, blob.type, blob),
    ];
    a.dispose();
    b.dispose();
    for (const reader of remaining) await expect(reader!.resourceToBytes("missing")).rejects.toThrow("disposed");
    await readers[2]!.free();
  });
});
