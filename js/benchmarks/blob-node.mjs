// Node driver for the Blob experiment, using the Node client.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Reader, Builder, CallbackSigner, Context } from "../../../c2pa-js/packages/c2pa-node/dist/index.js";
import { createClient } from "../src/node/client.mjs";
import { experiment } from "./blob-experiment.mjs";
import { blobFingerprints } from "../test/evidence.mjs";

const folder = new URL("../generated/", import.meta.url);
const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder)));
const metadata = JSON.parse(await readFile(new URL("benchmark.json", folder)));
const definition = metadata.definitions.small;
const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", folder)),
  { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
const certs = fixture.signing.certs.map((cert) => Buffer.from(cert));
const pem = Buffer.from(certs.map((cert) => `-----BEGIN CERTIFICATE-----\n${cert.toString("base64")
  .match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`).join(""));
const context = new Context(metadata.settings);
async function create(variant) {
  if (variant === "existing") return {
    async read(bytes) {
      const reader = await Reader.fromAsset({ buffer: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength),
        mimeType: "image/jpeg" }, context);
      if (!reader) throw new Error("missing existing reader");
      return { report: reader.json() };
    },
    async sign(bytes, definition, signing) {
      const builder = await Builder.withJsonAsync(definition, context);
      const destination = { buffer: null };
      const signer = CallbackSigner.newSigner({ alg: "es256", certs: [pem], reserveSize: 10000, directCoseHandling: false },
        async (data) => Buffer.from(await signing(data)));
      const manifest = await builder.signAsync(signer, {
        buffer: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength), mimeType: "image/jpeg",
      }, destination);
      return { asset: destination.buffer, manifest };
    },
    async close() {},
  };
  const client = createClient();
  return {
    read: (asset) => client.read(asset, { settings: fixture.settings, now: fixture.now }),
    sign: (asset, definition, signing) => client.sign(asset, definition, { alg: "es256", certs, sign: signing }),
    close: () => client.dispose(),
  };
}
let timer;
let peak;
let count;
const meter = {
  async current() { return process.memoryUsage().rss },
  async start() {
    peak = process.memoryUsage().rss;
    count = 1;
    timer = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); count++ }, 5);
    return peak;
  },
  async stop() {
    if (!timer) return;
    clearInterval(timer); timer = undefined;
    peak = Math.max(peak, process.memoryUsage().rss);
    return { peak, samples: count };
  },
};
const small = await readFile(new URL("benchmark-small.jpg", folder));
const jpeg = await readFile(new URL("benchmark-small-source.jpg", folder));
await mkdir(new URL("../results/", import.meta.url), { recursive: true });
const selected = process.argv[2];
if (!selected) {
  const preparation = createClient();
  try {
  for (const [name, size] of [["small", jpeg.length], ["medium", 8 * 1024 * 1024], ["large", 64 * 1024 * 1024]]) {
    const bytes = new Uint8Array(size);
    bytes.set(jpeg);
    const built = await preparation.sign(bytes, definition, { alg: "es256", certs, sign });
    await writeFile(new URL(`blob-${name}-source.jpg`, folder), bytes);
    await writeFile(new URL(`blob-${name}.jpg`, folder), built.asset);
  }
  } finally { await preparation.dispose() }
}
const results = {};
for (const name of ["small", "medium", "large"]) {
  if (!selected) {
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--expose-gc", fileURLToPath(import.meta.url), name], { stdio: "inherit" });
      child.on("error", reject);
      child.on("exit", (code, signal) => code === 0 ? resolve() :
        reject(new Error(`Node ${name} failed: ${signal ?? code}`)));
    });
    results[name] = JSON.parse(await readFile(new URL(`../results/blob-node-${name}.json`, import.meta.url)));
    continue;
  }
  if (name !== selected) continue;
  console.log(`Node ${name}: starting isolated process`);
  const signedBytes = await readFile(new URL(`blob-${name}.jpg`, folder));
  const input = {
    signedBytes,
    async load(variant, signed) {
      const path = new URL(`blob-${name}${signed ? "" : "-source"}.jpg`, folder);
      if (variant === "bytes" || variant === "existing") return readFile(path);
      const blob = new Blob([await readFile(path)], { type: "image/jpeg" });
      return variant === "file" ? new File([blob], "source.jpg", { type: "image/jpeg" }) : blob;
    },
  };
  results[name] = await experiment({ create, input, small, definition, sign, meter });
  await writeFile(new URL(`../results/blob-node-${name}.json`, import.meta.url), JSON.stringify(results[name], null, 2));
  console.log(`Node ${name}: ${results[name].samples.length} operations validated`);
  // Existing native handles have no public free API. Finalize only after
  // measurements, so GC does not change the measured operation contract.
  globalThis.gc?.();
}
if (!selected) await writeFile(new URL("../results/blob-node.json", import.meta.url), JSON.stringify({
  measuredAt: new Date().toISOString(), node: process.version, platform: process.platform, arch: process.arch,
  memory: "fresh process per asset size, excluding fixture generation; process RSS including all Worker isolates; 5 ms sampling plus endpoint; no forced GC",
  existingInput: "Buffer (existing Node SDK does not use browser File/Blob contract)",
  blobInput: "memory-backed Blob/File; Node 24.18 cannot clone fs.openAsBlob into a Worker",
  provenance: JSON.parse(await readFile(new URL("existing-sdk/provenance.json", folder))),
  fingerprints: await blobFingerprints(), results,
}, null, 2));
