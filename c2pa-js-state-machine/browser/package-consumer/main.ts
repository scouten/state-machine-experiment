import * as inline from "c2pa-js-state-machine/inline";
import * as worker from "c2pa-js-state-machine/worker";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import workerSrc from "./worker.ts?worker&url";
import directWorkerSrc from "c2pa-js-state-machine/worker-entry?worker&url";

const bytes = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
async function run() {
  Date.now = () => Date.parse("2026-09-01T00:00:00Z");
  const response = await fetch("/fixtures.json");
  check(response.ok, "Missing consumer test fixtures");
  const fixtures = await response.json() as {
    source: string; cert: string; key: string; definition: Record<string, unknown>;
  };
  const sourceBytes = bytes(fixtures.source);
  const source = new Blob([sourceBytes], { type: "image/jpeg" });
  const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
  const settings = { trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } };
  const key = await crypto.subtle.importKey("pkcs8", bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, "")),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  check(!key.extractable, "Signing key must stay caller-owned");
  const signer: inline.Signer = {
    alg: "es256", certs: [bytes(fixtures.cert)],
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
    },
  };
  const module = await WebAssembly.compile(await (await fetch(wasmSrc)).arrayBuffer());
  const mode = new URL(location.href).searchParams.get("mode") === "module" ? "module" : "url";
  const wasm = mode === "module" ? module : wasmSrc;
  const inlineClient = await inline.createC2pa({ wasmSrc: wasm, settings });
  const workerClient = await worker.createC2pa({ wasmSrc: wasm, workerSrc: new URL(workerSrc, location.href), settings });
  const clients = [inlineClient, workerClient];
  const results: string[] = [];
  try {
    const direct = await worker.createC2pa({ wasmSrc: wasm, workerSrc: new URL(directWorkerSrc, location.href) });
    try {
      check(await direct.reader.fromBlob("image/jpeg", new Blob([Uint8Array.of(0xff, 0xd8, 0xff, 0xd9)])) === null,
        "Direct packaged Worker entry did not read unsigned JPEG");
      check(direct.liveResources === 0, "Direct Worker leaked a reader");
    } finally { direct.dispose() }
    for (const [index, client] of clients.entries()) {
      // Runtime facades share the implemented reader/builder method shapes.
      const builder = index === 0
        ? await inline.Builder.fromDefinition(inlineClient, fixtures.definition)
        : await worker.Builder.fromDefinition(workerClient, fixtures.definition);
      const result = await builder.sign(signer, "image/jpeg", source);
      await builder.free();
      for (const target of clients) {
        const reader = await target.reader.fromBlob("image/jpeg",
          new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" }));
        check(reader, "Signed output must have a reader");
        const report = await reader.json();
        check(report.validation_state === "Trusted", JSON.stringify(report));
        await reader.free();
      }
      const detachedBuilder = index === 0
        ? await inline.Builder.fromDefinition(inlineClient, fixtures.definition)
        : await worker.Builder.fromDefinition(workerClient, fixtures.definition);
      const detached = await detachedBuilder.signDetached(signer, source);
      await detachedBuilder.free();
      check(detached.asset.length === source.size, "Detached asset length changed");
      check(detached.asset.every((value, offset) => value === sourceBytes[offset]), "Detached bytes changed");
      const reader = await client.reader.fromBlob("image/jpeg", source, settings, detached.manifest);
      check(reader, "Detached store must read");
      check((await reader.json()).validation_state === "Trusted", "Detached output untrusted");
      await reader.free();
      let rejected = false;
      try { await client.reader.fromBlob("image/jpeg", new Blob([Uint8Array.of(1, 2)]), settings) }
      catch { rejected = true }
      check(rejected, "Malformed asset unexpectedly accepted");
      check(client.liveResources === 0, "Resource leak");
      results.push(`${index === 0 ? "inline" : "worker"}-${mode}`);
    }
  } finally { for (const client of clients) client.dispose() }
  return results;
}
run().then((paths) => {
  document.body.dataset.result = JSON.stringify({ ok: true, paths });
}, (cause: unknown) => {
  document.body.dataset.result = JSON.stringify({ ok: false, error: cause instanceof Error ? cause.message : String(cause) });
});
