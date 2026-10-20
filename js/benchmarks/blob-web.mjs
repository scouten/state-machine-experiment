// In-page half of the Blob experiment: runs it with the browser client.
import { createClient } from "../src/browser/client.mjs";
import { createC2pa, Reader, Builder, Context } from "../generated/existing-sdk/index.js";
import { coseSigner } from "./sdk-benchmark.mjs";
import { experiment } from "./blob-experiment.mjs";

/** Runs the named experiment variant in the current page and returns its report. */
export async function run(name) {
  const fixture = await (await fetch("/generated/fixtures.json")).json();
  const metadata = await (await fetch("/generated/benchmark.json")).json();
  const definition = metadata.definitions.small;
  const load = async (path) => new Uint8Array(await (await fetch(`/generated/${path}`)).arrayBuffer());
  const key = await crypto.subtle.importKey("pkcs8", await load("test-signer.pk8"),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
  const sdk = await createC2pa({ wasmSrc: await WebAssembly.compile(await load("existing-sdk/c2pa_bg.wasm")) });
  const context = new Context(metadata.settings);
  const sourceFile = document.querySelector("#source").files[0];
  const signedFile = document.querySelector("#signed").files[0];
  const signedBytes = new Uint8Array(await signedFile.arrayBuffer());
  const small = await load("benchmark-small.jpg");
  async function create(variant) {
    if (variant === "existing") {
      const cleanup = [];
      return {
        async read(input) {
          const reader = await Reader.fromBlob(sdk, "image/jpeg",
            input instanceof Blob ? input : new Blob([input]), context);
          if (!reader) throw new Error("missing existing reader");
          cleanup.push(() => reader.free());
          return { report: await reader.json() };
        },
        async sign(input, definition, signing) {
          const builder = await Builder.fromDefinition(sdk, definition, context);
          cleanup.push(() => builder.free());
          return builder.signAndGetManifestBytes({
            alg: "es256", reserveSize: async () => 10000,
            sign: (claim, size) => coseSigner(claim, size, new Uint8Array(fixture.signing.certs[0]), signing),
          }, "image/jpeg", input);
        },
        async cleanup() { while (cleanup.length) await cleanup.shift()() },
        async close() { await this.cleanup() },
      };
    }
    const client = createClient();
    return {
      read: (input) => client.read(input, { settings: fixture.settings, now: fixture.now }),
      sign: (input, definition, signing) => client.sign(input, definition, {
        alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)), sign: signing,
      }),
      close: () => client.dispose(),
    };
  }
  try {
    const result = await experiment({
      create, small, definition, sign,
      meter: { start: () => globalThis.memoryStart(), stop: () => globalThis.memoryStop(),
        current: () => globalThis.memoryCurrent() },
      input: {
        signedBytes,
        async load(variant, signed) {
          const file = signed ? signedFile : sourceFile;
          if (variant === "bytes") return new Uint8Array(await file.arrayBuffer());
          if (variant === "blob") return file.slice(0, file.size, file.type);
          return file;
        },
      },
    });
    return { name, userAgent: navigator.userAgent, ...result };
  } finally { sdk.dispose() }
}
