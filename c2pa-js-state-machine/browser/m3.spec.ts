import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { Builder, Context, createC2pa, Reader, type Runtime, type Signer } from "c2pa-js-state-machine/inline";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };
import type { RemoteManifestOptions } from "../src/remote.ts";
import type { OcspOptions } from "../src/ocsp.ts";
import { createC2pa as createLegacy, Reader as LegacyReader, Context as LegacyContext } from "@contentauth/c2pa-web";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";

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

function tiffSource(little: boolean, big: boolean): Uint8Array {
  const header = big ? 16 : 8;
  const count = big ? 8 : 2;
  const entry = big ? 20 : 12;
  const word = big ? 8 : 4;
  const pixels = header + count + 9 * entry + word;
  const output = new Uint8Array(pixels + 1);
  const view = new DataView(output.buffer);
  const uint = (offset: number, value: number, width: number) => {
    if (width === 8) view.setBigUint64(offset, BigInt(value), little);
    else if (width === 4) view.setUint32(offset, value, little);
    else view.setUint16(offset, value, little);
  };
  output.set(little ? [0x49, 0x49] : [0x4d, 0x4d]);
  uint(2, big ? 43 : 42, 2);
  if (big) { uint(4, 8, 2); uint(8, header, 8) }
  else uint(4, header, 4);
  uint(header, 9, count);
  // One uncompressed 8-bit grayscale pixel, with no manifest tag.
  for (const [i, [tag, type, value]] of [
    [256, 4, 1], [257, 4, 1], [258, 3, 8], [259, 3, 1], [262, 3, 1],
    [273, 4, pixels], [277, 3, 1], [278, 4, 1], [279, 4, 1],
  ].entries()) {
    const at = header + count + i * entry;
    uint(at, tag, 2);
    uint(at + 2, type, 2);
    uint(at + 4, 1, word);
    uint(at + 4 + word, value, type === 3 ? 2 : 4);
  }
  output[pixels] = 0x7f;
  return output;
}
const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
const trusted = () => new Context({ trust: { trustAnchors: root }, verify: { ocspFetch: false, verifyTrust: true } });
const runtimes: Runtime[] = [];

interface OcspFixture {
  now: number;
  origin: string;
  certs: Record<string, string>;
  root: string;
  rootDer: string;
  key: string;
}

async function ocspAsset(client: Runtime, fixture: OcspFixture, mode: string) {
  const key = await crypto.subtle.importKey("pkcs8", bytes(fixture.key.replace(/-----[^-]+-----|\s/g, "")),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const builder = await Builder.fromDefinition(client, fixtures.definition);
  try {
    return await builder.sign({
      alg: "es256", certs: [bytes(fixture.certs[mode]), bytes(fixture.rootDer)],
      async sign(data) {
        return new Uint8Array(await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
      },
    }, "image/jpeg", storeFreeSource());
  } finally { await builder.free() }
}

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

function remoteAsset(url: string): Blob {
  const escaped = url.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
  const packet = new TextEncoder().encode(`http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:d="http://purl.org/dc/terms/" d:provenance="${escaped}"/></rdf:RDF></x:xmpmeta>`);
  const length = packet.length + 2;
  const input = storeFreeBytes();
  return new Blob([new Uint8Array(input.subarray(0, 2)), Uint8Array.of(0xff, 0xe1, length >> 8, length & 0xff),
    packet, new Uint8Array(input.subarray(2))], { type: "image/jpeg" });
}

function remoteOptions(overrides: Partial<RemoteManifestOptions> = {}): RemoteManifestOptions {
  return { allowedOrigins: [location.origin], maxBytes: 64 * 1024, timeoutMs: 2000, ...overrides };
}

async function publish(path: string, manifest: Uint8Array) {
  const response = await fetch(path, { method: "POST", body: new Uint8Array(manifest) });
  expect(response.status).toBe(204);
}

async function detached(client: Runtime, asset: Blob) {
  const builder = await Builder.fromDefinition(client, fixtures.definition);
  try { return await builder.signDetached(await signer(), asset) }
  finally { await builder.free() }
}

  describe("M3 browser OCSP host", () => {
    afterEach(() => {
      for (const instance of runtimes.splice(0)) {
        instance.dispose();
        expect(instance.liveResources).toBe(0);
      }
      vi.restoreAllMocks();
    });
    const fixture = async () => {
      const result = await (await fetch("/__m3/ocsp/fixtures")).json() as OcspFixture;
      vi.spyOn(Date, "now").mockReturnValue(result.now);
      return result;
    };
    const options = (f: OcspFixture, overrides: Partial<OcspOptions> = {}): OcspOptions => ({
      allowedOrigins: [f.origin], maxBytes: 64 * 1024, timeoutMs: 2000, ...overrides,
    });
    const context = (f: OcspFixture) => new Context({ trust: { trustAnchors: f.root }, verify: { ocspFetch: false } });
    const statuses = async (reader: Reader | null) => {
      expect(reader).not.toBeNull();
      const report = await reader!.manifestStore();
      return { state: report.validation_state, ...report.validation_results.activeManifest };
    };

    test("OCSP stays off by default and enabled signed responses establish non-revocation", async () => {
      const f = await fixture();
      const client = await runtime();
      const output = await ocspAsset(client, f, "good");
      const asset = new Blob([new Uint8Array(output.asset)], { type: "image/jpeg" });
      const before = await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>;
      const offline = await statuses(await Reader.fromBlob(client, "image/jpeg", asset, context(f)));
      expect(offline.state).toBe("Trusted");
      expect(offline.informational).toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.skipped" }));
      const after = await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>;
      expect(after.good).toBe(before.good);
      const online = await statuses(await Reader.fromBlob(client, "image/jpeg", asset, context(f),
        undefined, undefined, options(f)));
      expect(online.state, JSON.stringify(online)).toBe("Trusted");
      expect(online.success).toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.notRevoked" }));
      const enabled = await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>;
      expect(enabled.good).toBe(before.good + 1);
      await expect(Reader.fromBlob(client, "image/jpeg", asset,
        new Context({ verify: { ocspFetch: true } }))).rejects.toThrow(/Unsupported reader setting: verify.ocspFetch/);
    });

    test("authenticated revoked OCSP invalidates the active manifest while unauthenticated DER does not", async () => {
      const f = await fixture();
      const client = await runtime();
      for (const mode of ["revoked", "malformed"]) {
        const output = await ocspAsset(client, f, mode);
        const report = await statuses(await Reader.fromBlob(client, "image/jpeg",
          new Blob([new Uint8Array(output.asset)]), context(f), undefined, undefined, options(f)));
        expect(report.state).toBe(mode === "revoked" ? "Invalid" : "Trusted");
        expect(mode === "revoked" ? report.failure : report.informational).toContainEqual(
          expect.objectContaining({ code: `signingCredential.ocsp.${mode === "revoked" ? "revoked" : "inaccessible"}` }));
      }
    });

    test("OCSP policy CORS HTTP redirects and streamed limits record inaccessible rather than inventing revocation", async () => {
      const f = await fixture();
      const client = await runtime();
      const before = await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>;
      for (const mode of ["good", "no-cors", "unavailable", "redirect", "oversize"]) {
        const output = await ocspAsset(client, f, mode);
        const report = await statuses(await Reader.fromBlob(client, "image/jpeg",
          new Blob([new Uint8Array(output.asset)]), context(f), undefined, undefined,
          options(f, mode === "good" ? { allowedOrigins: [location.origin] } : {})));
        expect(report.state).toBe("Trusted");
        expect(report.informational).toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.inaccessible" }));
      }
      const after = await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>;
      // Denial and redirect rejection must not reach the permitted destination.
      expect(after.good).toBe(before.good);
      expect(after["no-cors"]).toBe(before["no-cors"]);
    });

    test("OCSP header body deadlines and in-flight cancellation preserve fail-open reporting and allow retry", async () => {
      const f = await fixture();
      const client = await runtime();
      for (const mode of ["slow", "slow-body"]) {
        const output = await ocspAsset(client, f, mode);
        const asset = new Blob([new Uint8Array(output.asset)]);
        const report = await statuses(await Reader.fromBlob(client, "image/jpeg", asset, context(f),
          undefined, undefined, options(f, { timeoutMs: 40 })));
        expect(report.state).toBe("Trusted");
        expect(report.informational).toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.inaccessible" }));
        const controller = new AbortController();
        const before = (await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>)[mode];
        const pending = Reader.fromBlob(client, "image/jpeg", asset, context(f), undefined, undefined,
          options(f, { signal: controller.signal }));
        for (let i = 0; i < 30; i++) {
          if ((await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>)[mode] > before) break;
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        expect((await (await fetch("/__m3/ocsp/stats")).json() as Record<string, number>)[mode]).toBeGreaterThan(before);
        controller.abort(new Error("OCSP caller cancellation"));
        const cancelled = await statuses(await pending);
        expect(cancelled.informational).toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.inaccessible" }));
        const retry = await statuses(await Reader.fromBlob(client, "image/jpeg", asset, context(f),
          undefined, undefined, options(f)));
        expect(retry.success, JSON.stringify(retry)).toContainEqual(expect.objectContaining({ code: "signingCredential.ocsp.notRevoked" }));
      }
    });

  });

describe("M3 detached and remote manifests", () => {
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

  test("discovers JPEG XMP and fetches a trusted remote manifest only with explicit host opt-in", async () => {
    const client = await runtime();
    const path = "/__m3/trusted";
    const asset = remoteAsset(new URL(path, location.href).href);
    const output = await detached(client, asset);
    await publish(path, output.manifest);
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    expect(await Reader.fromBlob(client, "image/jpeg", asset, trusted())).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
    const reader = await Reader.fromBlob(client, "image/jpeg", asset, trusted(), undefined, remoteOptions());
    expect(reader).not.toBeNull();
    expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
    expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const init = fetchSpy.mock.calls[0][1];
    expect(init).toMatchObject({ credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
    const changed = new Blob([asset, Uint8Array.of(1)], { type: asset.type });
    const invalid = await Reader.fromBlob(client, "image/jpeg", changed, trusted(), undefined, remoteOptions());
    expect((await invalid!.manifestStore()).validation_state).toBe("Invalid");
  });

  test("embedded and supplied detached stores take precedence over remote fetching", async () => {
    const client = await runtime();
    const asset = remoteAsset("https://denied.invalid/store");
    const output = await detached(client, asset);
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    let embedded: { asset: Uint8Array; manifest: Uint8Array };
    try { embedded = await builder.sign(await signer(), "image/jpeg", asset) }
    finally { await builder.free() }
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    for (const [input, store] of [
      [new Blob([new Uint8Array(embedded.asset)]), undefined],
      [asset, output.manifest],
    ] as const) {
      const reader = await Reader.fromBlob(client, "image/jpeg", input, trusted(), store, remoteOptions());
      expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("remote transport denies unauthorized destinations before making any network request", async () => {
    const client = await runtime();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    for (const url of ["https://denied.invalid/store", "file:///store",
      `http://user:pass@${location.host}/__m3/store`, `${location.origin}/__m3/store#fragment`]) {
      await expect(Reader.fromBlob(client, "image/jpeg", remoteAsset(url), trusted(), undefined, remoteOptions()))
        .rejects.toThrow(/denied by host policy/);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("remote transport rejects redirects HTTP failures oversized and malformed bodies", async () => {
    const client = await runtime();
    await publish("/__m3/limits", Uint8Array.of(1, 2, 3));
    for (const [path, options, message] of [
      ["/__m3/limits?redirect", remoteOptions(), /remote manifest host failed/],
      ["/__m3/missing", remoteOptions(), /HTTP status 404/],
      ["/__m3/limits", remoteOptions({ maxBytes: 2 }), /exceeds byte limit/],
      ["/__m3/limits?chunked", remoteOptions({ maxBytes: 2 }), /exceeds byte limit/],
      ["/__m3/limits", remoteOptions(), /C2pa\(Read/],
    ] as const) {
      await expect(Reader.fromBlob(client, "image/jpeg", remoteAsset(new URL(path, location.href).href),
        trusted(), undefined, options)).rejects.toThrow(message);
    }
  });

  test("remote deadlines cover response headers and body and caller cancellation rejects", async () => {
    const client = await runtime();
    await publish("/__m3/slow", Uint8Array.of(1, 2, 3));
    for (const query of ["slow", "slow-body"]) {
      await expect(Reader.fromBlob(client, "image/jpeg",
        remoteAsset(`${location.origin}/__m3/slow?${query}`), trusted(), undefined,
        remoteOptions({ timeoutMs: 25 }))).rejects.toThrow(/deadline|abort/i);
    }
    const controller = new AbortController();
    const promise = Reader.fromBlob(client, "image/jpeg",
      remoteAsset(`${location.origin}/__m3/slow?slow`), trusted(), undefined,
      remoteOptions({ signal: controller.signal }));
    await new Promise((resolve) => setTimeout(resolve, 25));
    controller.abort(new Error("caller cancelled"));
    await expect(promise).rejects.toThrow(/caller cancelled/);
  });

  test("cross-origin fetching obeys CORS and a failed read can be retried explicitly", async () => {
    const client = await runtime();
    const other = new URL((await (await fetch("/__m3/origin")).json() as { origin: string }).origin);
    const allowed = remoteOptions({ allowedOrigins: [other.origin] });
    await publish("/__m3/cors-denied", Uint8Array.of(1, 2, 3));
    await expect(Reader.fromBlob(client, "image/jpeg",
      remoteAsset(`${other.origin}/__m3/cors-denied`), trusted(), undefined, allowed))
      .rejects.toThrow(/remote manifest host failed/);
    const asset = remoteAsset(`${other.origin}/__m3/cors-retry?cors`);
    const output = await detached(client, asset);
    await expect(Reader.fromBlob(client, "image/jpeg", asset, trusted(), undefined, allowed))
      .rejects.toThrow(/HTTP status 404/);
    await publish("/__m3/cors-retry", output.manifest);
    const reader = await Reader.fromBlob(client, "image/jpeg", asset, trusted(), undefined, allowed);
    expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
    expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
  });

  test("TIFF and BigTIFF in both byte orders sign read sniff and bind two separate exclusions", async () => {
    const client = await runtime();
    for (const big of [false, true]) for (const little of [false, true]) {
      const input = tiffSource(little, big);
      expect(await Reader.fromBlob(client, undefined, new Blob([new Uint8Array(input)]), trusted())).toBeNull();
      const builder = await Builder.fromDefinition(client, fixtures.definition);
      let output;
      try { output = await builder.sign(await signer(), "image/tiff", new Blob([new Uint8Array(input)])) }
      finally { await builder.free() }
      const asset = new Blob([new Uint8Array(output.asset)]);
      const reader = await Reader.fromBlob(client, undefined, asset, trusted());
      const report = await reader!.manifestStore();
      expect(report.validation_state).toBe("Trusted");
      const active = report.manifests[report.active_manifest!] as {
        assertions: { label: string; data: { exclusions: { start: number; length: number }[] } }[];
      };
      const exclusions = active.assertions.find((assertion) => assertion.label === "c2pa.hash.data")!.data.exclusions;
      expect(exclusions).toHaveLength(2);
      expect(exclusions[0].start + exclusions[0].length).toBeLessThan(exclusions[1].start);
      expect(exclusions[1].start + exclusions[1].length).toBe(output.asset.length);
      const damaged = new Uint8Array(output.asset);
      damaged[input.length - 1] ^= 1;
      const invalid = await Reader.fromBlob(client, "tiff", new Blob([damaged]), trusted());
      expect((await invalid!.manifestStore()).validation_results.activeManifest.failure)
        .toContainEqual(expect.objectContaining({ code: "assertion.dataHash.mismatch" }));
      const detachedOutput = await detached(client, new Blob([new Uint8Array(input)]));
      const detachedReader = await Reader.fromBlob(client, "image/tiff", new Blob([new Uint8Array(input)]),
        trusted(), detachedOutput.manifest);
      expect((await detachedReader!.manifestStore()).validation_state).toBe("Trusted");
    }
    await expect(Reader.fromBlob(client, "image/tiff", new Blob([Uint8Array.of(0, 1, 2)]), trusted()))
      .rejects.toThrow(/C2pa\(Read/);
  });

  test("legacy validates state-machine TIFF output and shared DNG aliases use the TIFF handler", async () => {
    const client = await runtime();
    const legacy = await createLegacy({ wasmSrc: legacyWasmSrc });
    try {
      for (const little of [false, true]) {
        const builder = await Builder.fromDefinition(client, fixtures.definition);
        let output;
        try { output = await builder.sign(await signer(), "tiff", new Blob([new Uint8Array(tiffSource(little, false))])) }
        finally { await builder.free() }
        const asset = new Blob([new Uint8Array(output.asset)]);
        const oldReader = await LegacyReader.fromBlob(legacy, "image/tiff", asset,
          new LegacyContext({ trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } }));
        try {
          expect((await oldReader!.manifestStore()).validation_state).toBe("Trusted");
          expect(await oldReader!.activeLabel()).toBe(fixtures.definition.label);
        } finally { await oldReader?.free() }
        for (const format of ["IMAGE/TIFF", "tif", "dng", "image/dng", "image/x-adobe-dng"]) {
          const reader = await Reader.fromBlob(client, format, asset, trusted());
          expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
        }
      }
    } finally { legacy.dispose() }
  });
});
