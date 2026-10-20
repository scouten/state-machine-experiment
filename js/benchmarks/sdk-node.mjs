// Node side of the SDK comparison: the existing c2pa-node SDK and this
// workspace's shared host run the same benchmark and write results/ with
// source fingerprints as provenance.
import { Reader, Builder, CallbackSigner, Context } from "../../../c2pa-js/packages/c2pa-node/dist/index.js";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createClient } from "../src/node/client.mjs";
import { benchmark, validateReport } from "./sdk-benchmark.mjs";
import { sdkFingerprints } from "../test/evidence.mjs";

const folder = new URL("../generated/", import.meta.url);
await mkdir(new URL("../results/", import.meta.url), { recursive: true });
const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder)));
const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", folder)),
  { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
const certs = fixture.signing.certs.map((cert) => Buffer.from(cert));
const pemCerts = Buffer.from(certs.map((cert) =>
  `-----BEGIN CERTIFICATE-----\n${cert.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`).join(""));
const settings = { trust: { userAnchors: fixture.settings.trust.anchors[0].trust_anchors },
  verify: { ocspFetch: false, remoteManifestFetch: false, verifyAfterSign: false, verifyAfterReading: true, verifyTrust: true } };
const context = new Context(settings);
const proof = createClient();
const adapters = {
  existing: {
    async read(bytes) {
      const reader = await Reader.fromAsset({ buffer: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength), mimeType: "image/jpeg" }, context);
      if (!reader) throw new Error("existing SDK returned no reader");
      return reader.json();
    },
    async sign(bytes, definition, signing) {
      const builder = await Builder.withJsonAsync(definition, context);
      const destination = { buffer: null };
      const signer = CallbackSigner.newSigner({ alg: "es256", certs: [pemCerts], reserveSize: 10000, directCoseHandling: false },
        async (data) => Buffer.from(await signing(data)));
      const manifest = await builder.signAsync(signer, { buffer: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength),
        mimeType: "image/jpeg" }, destination);
      return { asset: destination.buffer, manifest };
    },
  },
  proof: {
    async read(bytes) { return (await proof.read(bytes, { settings: fixture.settings })).report },
    sign(bytes, definition, signing) { return proof.sign(bytes, definition, { alg: "es256", certs, sign: signing }) },
  },
};
try {
  const fixtures = {};
  const jpeg = await readFile(new URL("../../../c2pa-js/packages/c2pa-node/tests/fixtures/thumbnail.jpg", import.meta.url));
  if (await Reader.fromAsset({ buffer: jpeg, mimeType: "image/jpeg" }, context))
    throw new Error("benchmark source must be unsigned");
  for (const [name, size] of [["small", jpeg.length], ["large", 64 * 1024 * 1024]]) {
    const source = new Uint8Array(size);
    source.set(jpeg);
    const definition = structuredClone(fixture.signing.definition);
    definition.label = "urn:c2pa:00000000-0000-4000-8000-000000000002";
    // c2pa-rs 0.91 rejects the original minimal action without this field.
    definition.assertions[0].data.actions[0].digitalSourceType =
      "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";
    const { asset: signed } = await adapters.proof.sign(source, definition, sign);
    for (const adapter of Object.values(adapters)) validateReport(await adapter.read(signed), definition);
    await writeFile(new URL(`benchmark-${name}.jpg`, folder), signed);
    await writeFile(new URL(`benchmark-${name}-source.jpg`, folder), source);
    fixtures[name] = { source, signed, definition };
  }
  await writeFile(new URL("benchmark.json", folder), JSON.stringify({ definitions:
    Object.fromEntries(Object.entries(fixtures).map(([name, value]) => [name, value.definition])), settings }));
  const result = await benchmark(adapters, fixtures, sign);
  const provenance = JSON.parse(await readFile(new URL("existing-sdk/provenance.json", folder)));
  await writeFile(new URL("../results/sdk-node.json", import.meta.url),
    JSON.stringify({ measuredAt: new Date().toISOString(), node: process.version, platform: process.platform,
      arch: process.arch, provenance, fingerprints: await sdkFingerprints(), ...result }, null, 2));
  console.log(`Node SDK comparison: ${result.samples.length} measured operations; all outputs validated by both SDKs.`);
} finally { await proof.dispose() }
