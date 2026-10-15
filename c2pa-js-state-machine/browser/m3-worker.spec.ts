import { afterEach, describe, expect, test } from "vitest";
import { Builder, Context, createC2pa, Reader, type Runtime, type Signer } from "c2pa-js-state-machine/worker";
import { createC2pa as createInline, Reader as InlineReader } from "c2pa-js-state-machine/inline";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import workerSrc from "./clocked-worker.ts?worker&url";
import unclockedWorkerSrc from "c2pa-js-state-machine/worker-entry?worker&url";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };
import { createC2pa as createLegacy, Reader as LegacyReader, Context as LegacyContext } from "@contentauth/c2pa-web";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";

const bytes = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
const source = () => new Blob([bytes(fixtures.source)], { type: "image/jpeg" });
const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
const trusted = () => new Context({ trust: { trustAnchors: root }, verify: { ocspFetch: false, verifyTrust: true } });
const clients: Runtime[] = [];
async function runtime(wasm: string | WebAssembly.Module = wasmSrc): Promise<Runtime> {
  const client = await createC2pa({ wasmSrc: wasm, workerSrc: new URL(workerSrc, location.href) });
  clients.push(client);
  return client;
}
async function signer(): Promise<Signer> {
  const der = bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, ""));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  expect(key.extractable).toBe(false);
  return { alg: "es256", certs: [bytes(fixtures.cert)], async sign(data) {
    return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
  } };
}
async function output(client: Runtime) {
  const builder = await Builder.fromDefinition(client, fixtures.definition);
  try { return await builder.sign(await signer(), "image/jpeg", source()) }
  finally { await builder.free() }
}
async function timestampSetup() {
  const fixture = await (await fetch("/__m3/tsa/fixtures")).json() as {
    now: number; origin: string; root: string; cert: string; rootDer: string; key: string;
  };
  await new Promise((resolve) => setTimeout(resolve, Math.max(0, fixture.now - Date.now())));
  const client = await createC2pa({ wasmSrc, workerSrc: new URL(unclockedWorkerSrc, location.href) });
  clients.push(client);
  const key = await crypto.subtle.importKey("pkcs8", bytes(fixture.key.replace(/-----[^-]+-----|\s/g, "")),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signing: Signer = {
    alg: "es256", certs: [bytes(fixture.cert), bytes(fixture.rootDer)],
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
    },
  };
  const settings = { trust: { trustAnchors: fixture.root }, verify: { verifyTrust: true, ocspFetch: false } };
  return { client, fixture, signing, settings };
}
async function timestampResponse(url: string, request: Uint8Array): Promise<Uint8Array> {
  // Route the callback to same-origin loopback fixtures; no SDK network default.
  const response = await fetch(new URL(url).pathname, {
    method: "POST", headers: { "Content-Type": "application/timestamp-query", Accept: "application/timestamp-reply" },
    body: new Uint8Array(request),
  });
  if (!response.ok) throw new Error(`Test TSA returned ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

describe("M3 Worker", () => {
  afterEach(() => { for (const client of clients.splice(0)) { client.dispose(); expect(client.liveResources).toBe(0) } });
  test("URL and precompiled-module loading are isolated and failed initialization can retry", async () => {
    await expect(runtime("data:application/wasm;base64,AA==")).rejects.toThrow();
    const module = await WebAssembly.compile(await (await fetch(wasmSrc)).arrayBuffer());
    const [urlClient, moduleClient] = await Promise.all([runtime(), runtime(module)]);
    expect(urlClient).not.toBe(moduleClient);
    expect(await Reader.fromBlob(moduleClient, undefined, new Blob([Uint8Array.of(0xff, 0xd8, 0xff, 0xd9)]))).toBeNull();
    await expect(createC2pa({ wasmSrc, workerSrc: new URL("/missing-worker.js", location.href) })).rejects.toThrow();
  });
  test("caller-owned signing key produces trusted Worker and inline read-back without detaching inputs", async () => {
    const client = await runtime();
    const result = await output(client);
    const blob = new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" });
    const reader = await client.reader.fromBlob(undefined, blob, trusted().settings);
    expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
    expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
    expect(await reader!.json()).toEqual(await reader!.manifestStore());
    expect(await reader!.activeManifest()).toBeDefined();
    expect(Object.keys(reader!)).toEqual([]);
    expect(JSON.stringify(reader)).toBe("{}");
    const inline = await createInline({ wasmSrc });
    try {
      const other = await InlineReader.fromBlob(inline, "image/jpeg", blob, trusted());
      expect((await other!.json()).validation_state).toBe("Trusted");
    } finally { inline.dispose() }
    expect(result.asset.byteLength).toBeGreaterThan(0);
    await reader!.free();
    await reader!.free();
    await expect(reader!.json()).rejects.toThrow(/freed/);
    expect(client.liveResources).toBe(0);
    await expect(client.call({ method: "free", handle: 99999 })).rejects.toThrow(/Invalid Worker resource/);
  });
  test("detached output, malformed input and concurrent reads retain independent ownership", async () => {
    const client = await runtime();
    const builder = await client.builder.fromDefinition(fixtures.definition);
    const detached = await builder.signDetached(await signer(), source());
    expect(detached.asset).toEqual(bytes(fixtures.source));
    const readers = await Promise.all([
      Reader.fromBlob(client, "image/jpeg", source(), trusted(), detached.manifest),
      Reader.fromBlob(client, "image/jpeg", source(), trusted(), detached.manifest),
    ]);
    expect(client.liveResources).toBe(3);
    for (const reader of readers) expect((await reader!.json()).validation_state).toBe("Trusted");
    await expect(Reader.fromBlob(client, "image/jpeg", source(), trusted(), Uint8Array.of(1, 2))).rejects.toThrow();
    expect(client.liveResources).toBe(3);
    client.dispose();
    await expect(readers[0]!.json()).rejects.toThrow(/disposed/);
    await builder.free();
  });
  test("signing and timestamp callback failures reject explicitly and allow a fresh attempt", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    const signing = await signer();
    await expect(builder.sign({ ...signing, async sign() { throw new Error("caller signing failure") } },
      "image/jpeg", source())).rejects.toThrow(/caller signing failure/);
    let timestampCalls = 0;
    await expect(builder.sign({ ...signing, timeAuthorityUrl: "https://tsa.example.invalid",
      async sendTimestampRequest(url, request) {
        expect(url).toBe("https://tsa.example.invalid");
        expect(request.byteLength).toBeGreaterThan(0);
        timestampCalls++;
        throw new Error("caller timestamp failure");
      } }, "image/jpeg", source())).rejects.toThrow(/caller timestamp failure/);
    expect(timestampCalls).toBe(1);
    expect((await builder.sign(signing, "image/jpeg", source())).manifest.byteLength).toBeGreaterThan(0);
    await builder.free();
  });
  test("genuine Worker timestamps survive concurrent callback routing and inline/legacy validation", async () => {
    const { client, fixture, signing, settings } = await timestampSetup();
    const inline = await createInline({ wasmSrc });
    const legacy = await createLegacy({ wasmSrc: legacyWasmSrc });
    let calls = 0;
    try {
      const builders = await Promise.all([
        Builder.fromDefinition(client, { ...fixtures.definition, tsa_url: `${fixture.origin}/__m3/tsa/good` }),
        Builder.fromDefinition(client, { ...fixtures.definition, title: "Concurrent timestamp routing" }),
      ]);
      const requests: Uint8Array[] = [];
      const timestampSigner = { ...signing, timeAuthorityUrl: `${fixture.origin}/__m3/tsa/good`,
        async sendTimestampRequest(url: string, request: Uint8Array) {
          expect(url).toBe(`${fixture.origin}/__m3/tsa/good`);
          calls++;
          const snapshot = new Uint8Array(request);
          requests.push(snapshot);
          const reply = await timestampResponse(url, request);
          expect(request).toEqual(snapshot);
          return reply;
        } };
      const outputs = await Promise.all(builders.map((builder, index) => builder.sign({
        ...timestampSigner,
        timeAuthorityUrl: `${fixture.origin}/__m3/tsa/${index === 0 ? "refused" : "good"}`,
      }, "image/jpeg", source())));
      expect(calls).toBe(2);
      expect(requests[0]).not.toEqual(requests[1]);
      for (const result of outputs) {
        const blob = new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" });
        const reader = await Reader.fromBlob(client, "image/jpeg", blob, new Context(settings));
        const other = await InlineReader.fromBlob(inline, "image/jpeg", blob, new Context(settings));
        const old = await LegacyReader.fromBlob(legacy, "image/jpeg", blob, new LegacyContext(settings));
        try {
          const report = await reader!.json();
          expect(report.validation_state, JSON.stringify(report)).toBe("Trusted");
          expect(report.validation_results.activeManifest.success).toContainEqual(expect.objectContaining({ code: "timeStamp.validated" }));
          expect(await other!.json()).toEqual(report);
          const oldReport = await old!.json();
          expect(oldReport.validation_state, JSON.stringify(oldReport)).toBe("Trusted");
          expect(oldReport.validation_results?.activeManifest?.success).toContainEqual(expect.objectContaining({ code: "timeStamp.validated" }));
        } finally { await reader!.free(); await other!.free(); await old!.free() }
      }
      for (const builder of builders) await builder.free();
      expect(client.liveResources).toBe(0);
    } finally { inline.dispose(); legacy.dispose() }
  });
  test("refused and malformed Worker timestamps fail without fallback and the same builder can retry", async () => {
    const { client, fixture, signing, settings } = await timestampSetup();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    let calls = 0;
    const withAuthority = (mode: string): Signer => ({
      ...signing, timeAuthorityUrl: `${fixture.origin}/__m3/tsa/${mode}`,
      async sendTimestampRequest(url, request) { calls++; return await timestampResponse(url, request) },
    });
    await expect(builder.sign({ ...signing, timeAuthorityUrl: `${fixture.origin}/__m3/tsa/good` },
      "image/jpeg", source())).rejects.toThrow();
    expect(calls).toBe(0);
    for (const mode of ["refused", "malformed"])
      await expect(builder.sign(withAuthority(mode), "image/jpeg", source())).rejects.toThrow();
    expect(calls).toBe(2);
    const result = await builder.sign(withAuthority("good"), "image/jpeg", source());
    expect(calls).toBe(3);
    const reader = await Reader.fromBlob(client, "image/jpeg", new Blob([new Uint8Array(result.asset)]), new Context(settings));
    expect((await reader!.json()).validation_results.activeManifest.success)
      .toContainEqual(expect.objectContaining({ code: "timeStamp.validated" }));
    await reader!.free();
    await builder.free();
    expect(client.liveResources).toBe(0);
  });
  test("detached Worker timestamps validate and a genuine token for another imprint is rejected on reading", async () => {
    const { client, fixture, signing, settings } = await timestampSetup();
    const inline = await createInline({ wasmSrc });
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    try {
      for (const mode of ["good", "mismatch"]) {
        const result = await builder.signDetached({
          ...signing, timeAuthorityUrl: `${fixture.origin}/__m3/tsa/${mode}`,
          sendTimestampRequest: timestampResponse,
        }, source());
        expect(result.asset).toEqual(bytes(fixtures.source));
        const blob = new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" });
        const reader = await Reader.fromBlob(client, "image/jpeg", blob, new Context(settings), result.manifest);
        const other = await InlineReader.fromBlob(inline, "image/jpeg", blob, new Context(settings), result.manifest);
        try {
          const report = await reader!.json();
          expect(await other!.json()).toEqual(report);
          const bucket = mode === "good" ? "success" : "informational";
          expect(report.validation_results.activeManifest[bucket]).toContainEqual(expect.objectContaining({
            code: mode === "good" ? "timeStamp.validated" : "timeStamp.mismatch",
          }));
          expect(report.validation_state).toBe("Trusted");
          if (mode === "mismatch") {
            expect(report.validation_results.activeManifest.success)
              .not.toContainEqual(expect.objectContaining({ code: "timeStamp.validated" }));
          }
        } finally { await reader!.free(); await other!.free() }
      }
      await builder.free();
      expect(client.liveResources).toBe(0);
    } finally { inline.dispose() }
  });
  test("free and disposal during an in-flight callback reject work and do not hang", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    const signing = await signer();
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve });
    let finish!: (value: Uint8Array) => void;
    const pending = builder.sign({ ...signing, sign() {
      entered();
      return new Promise<Uint8Array>((resolve) => { finish = resolve });
    } }, "image/jpeg", source());
    const failure = expect(pending).rejects.toThrow(/freed|disposed/);
    await started;
    await expect(builder.sign(signing, "image/jpeg", source())).rejects.toThrow(/in-flight/);
    await builder.free();
    expect(client.liveResources).toBe(0);
    client.dispose();
    await failure;
    finish(new Uint8Array(64));
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  test("free during signing defers Wasm cleanup until the callback settles without leaking a handle", async () => {
    const client = await runtime();
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    const signing = await signer();
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve });
    let resume!: () => void;
    const gate = new Promise<void>((resolve) => { resume = resolve });
    const operation = builder.sign({ ...signing, async sign(data) {
      entered();
      await gate;
      return await signing.sign(data);
    } }, "image/jpeg", source());
    const rejected = expect(operation).rejects.toThrow(/freed/);
    await started;
    await builder.free();
    resume();
    await rejected;
    expect(client.liveResources).toBe(0);
    expect((await output(client)).manifest.byteLength).toBeGreaterThan(0);
    expect(client.liveResources).toBe(0);
  });
  test("Worker remote fetch remains opt-in and propagates in-flight cancellation and retry", async () => {
    const client = await runtime();
    const path = "/__m3/worker-remote";
    const url = `${location.origin}${path}?slow`;
    const packet = new TextEncoder().encode(`http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:d="http://purl.org/dc/terms/" d:provenance="${url}"/></rdf:RDF></x:xmpmeta>`);
    const length = packet.length + 2;
    const asset = new Blob([Uint8Array.of(0xff, 0xd8, 0xff, 0xe1, length >> 8, length & 0xff),
      packet, Uint8Array.of(0xff, 0xd9)], { type: "image/jpeg" });
    const builder = await Builder.fromDefinition(client, fixtures.definition);
    const detached = await builder.signDetached(await signer(), asset);
    await builder.free();
    expect((await fetch(path, { method: "POST", body: new Uint8Array(detached.manifest) })).status).toBe(204);
    expect(await Reader.fromBlob(client, undefined, asset, trusted())).toBeNull();
    const counts = async () => await (await fetch("/__m3/requests")).json() as Record<string, number>;
    expect((await counts())[path] ?? 0).toBe(0);
    const options = { allowedOrigins: [location.origin], maxBytes: 64 * 1024, timeoutMs: 2000 };
    const controller = new AbortController();
    const pending = Reader.fromBlob(client, undefined, asset, trusted(), undefined, { ...options, signal: controller.signal });
    const failed = expect(pending).rejects.toThrow(/caller Worker cancellation/);
    for (let i = 0; i < 100 && !(await counts())[path]; i++)
      await new Promise((resolve) => setTimeout(resolve, 5));
    expect((await counts())[path]).toBe(1);
    controller.abort(new Error("caller Worker cancellation"));
    await failed;
    expect(client.liveResources).toBe(0);
    const reader = await Reader.fromBlob(client, undefined, asset, trusted(), undefined, options);
    expect((await reader!.json()).validation_state).toBe("Trusted");
    await reader!.free();
    const preaborted = new AbortController();
    preaborted.abort(new Error("pre-aborted Worker fetch"));
    await expect(Reader.fromBlob(client, undefined, asset, trusted(), undefined,
      { ...options, signal: preaborted.signal })).rejects.toThrow(/pre-aborted/);
    expect((await counts())[path]).toBe(2);
  });
  test("Worker OCSP authenticates signed responses and preserves inaccessible-response policy", async () => {
    const fixture = await (await fetch("/__m3/ocsp/fixtures")).json() as {
      now: number; origin: string; certs: Record<string, string>; root: string; rootDer: string; key: string;
    };
    // Use the real Worker clock strictly after thisUpdate, rather than mutating production code.
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, fixture.now - Date.now())));
    const client = await createC2pa({ wasmSrc, workerSrc: new URL(unclockedWorkerSrc, location.href) });
    clients.push(client);
    const key = await crypto.subtle.importKey("pkcs8", bytes(fixture.key.replace(/-----[^-]+-----|\s/g, "")),
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const context = new Context({ trust: { trustAnchors: fixture.root }, verify: { ocspFetch: false } });
    const options = { allowedOrigins: [fixture.origin], maxBytes: 64 * 1024, timeoutMs: 2000 };
    for (const mode of ["good", "revoked", "malformed"]) {
      const builder = await Builder.fromDefinition(client, fixtures.definition);
      const result = await builder.sign({
        alg: "es256", certs: [bytes(fixture.certs[mode]), bytes(fixture.rootDer)],
        async sign(data) {
          return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
        },
      }, "image/jpeg", source());
      await builder.free();
      const reader = await Reader.fromBlob(client, "image/jpeg", new Blob([new Uint8Array(result.asset)]),
        context, undefined, undefined, options);
      const report = await reader!.json();
      expect(report.validation_state).toBe(mode === "revoked" ? "Invalid" : "Trusted");
      const bucket = mode === "good" ? "success" : mode === "revoked" ? "failure" : "informational";
      expect(report.validation_results.activeManifest[bucket]).toContainEqual(expect.objectContaining({
        code: `signingCredential.ocsp.${mode === "good" ? "notRevoked" : mode === "revoked" ? "revoked" : "inaccessible"}`,
      }));
      await reader!.free();
    }
    expect(client.liveResources).toBe(0);
  });
  test("external module Worker works under self-only CSP and fails explicitly when worker-src denies it", async () => {
    async function page(mode: "allow" | "deny"): Promise<{ ok: boolean; error?: string; violations: string[] }> {
      const iframe = document.createElement("iframe");
      let listener: (event: MessageEvent) => void;
      let deadline: ReturnType<typeof setTimeout>;
      try {
        return await new Promise((resolve, reject) => {
          listener = (event) => {
            if (event.source === iframe.contentWindow && event.origin === location.origin &&
                event.data?.kind === "c2pa-worker-csp") resolve(event.data);
          };
          window.addEventListener("message", listener);
          deadline = setTimeout(() => reject(new Error("CSP fixture did not finish")), 10_000);
          iframe.src = `/__m3-worker-csp?mode=${mode}`;
          document.body.append(iframe);
        });
      } finally {
        window.removeEventListener("message", listener!);
        clearTimeout(deadline!);
        iframe.remove();
      }
    }
    const allowed = await page("allow");
    expect(allowed).toMatchObject({ ok: true, violations: [] });
    const denied = await page("deny");
    expect(denied.ok).toBe(false);
    expect(denied.error).toBeTruthy();
    expect(denied.violations).toContain("worker-src");
  });
});
