// In-page half of the browser SDK comparison: runs the existing c2pa-web SDK
// and the shared host through the same benchmark inside one browser.
import { createClient } from "../src/browser/client.mjs";
import { createC2pa, Reader, Builder, Context } from "../generated/existing-sdk/index.js";
import { benchmark, coseSigner } from "./sdk-benchmark.mjs";

/** Runs the comparison in the current page and returns its report. */
export async function run() {
  const fixture = await (await fetch("/generated/fixtures.json")).json();
  const metadata = await (await fetch("/generated/benchmark.json")).json();
  const load = async (path) => new Uint8Array(await (await fetch(`/generated/${path}`)).arrayBuffer());
  const key = await crypto.subtle.importKey("pkcs8", await load("test-signer.pk8"),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
  const wasm = await WebAssembly.compile(await load("existing-sdk/c2pa_bg.wasm"));
  const sdk = await createC2pa({ wasmSrc: wasm });
  const proof = createClient();
  const context = new Context(metadata.settings);
  const blobs = new WeakMap();
  const blob = (bytes) => {
    if (!blobs.has(bytes)) blobs.set(bytes, new Blob([bytes], { type: "image/jpeg" }));
    return blobs.get(bytes);
  };
  const cleanup = [];
  const adapters = {
    existing: {
      async read(bytes) {
        const reader = await Reader.fromBlob(sdk, "image/jpeg", blob(bytes), context);
        if (!reader) throw new Error("existing SDK returned no reader");
        cleanup.push(() => reader.free());
        return reader.json();
      },
      async sign(bytes, definition, signing) {
        const builder = await Builder.fromDefinition(sdk, definition, context);
        cleanup.push(() => builder.free());
        return builder.signAndGetManifestBytes({
          alg: "es256",
          reserveSize: async () => 10000,
          sign: (claim, size) => coseSigner(claim, size, new Uint8Array(fixture.signing.certs[0]), signing),
        }, "image/jpeg", blob(bytes));
      },
      async cleanup() { while (cleanup.length) await cleanup.shift()() },
    },
    proof: {
      async read(bytes) { return (await proof.read(bytes, { settings: fixture.settings })).report },
      sign(bytes, definition, signing) {
        return proof.sign(bytes, definition, { alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)), sign: signing });
      },
    },
  };
  try {
    const fixtures = {};
    for (const name of ["small", "large"]) {
      const source = await load(`benchmark-${name}-source.jpg`);
      const signed = await load(`benchmark-${name}.jpg`);
      blob(source);
      blob(signed);
      fixtures[name] = { source, signed, definition: metadata.definitions[name] };
    }
    return { ...(await benchmark(adapters, fixtures, sign)), userAgent: navigator.userAgent };
  } finally {
    await adapters.existing.cleanup();
    await proof.dispose();
    sdk.dispose();
  }
}
