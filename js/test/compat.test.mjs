// Compatibility facade tests: the same client scenarios run through the
// existing c2pa-node SDK and the facade, and unsupported options are rejected.
import assert from "node:assert/strict";
import test from "node:test";
import { readFile, writeFile, mkdtemp, rm, readdir, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as existing from "../../../c2pa-js/packages/c2pa-node/dist/index.js";
import { createNodeCompat } from "../src/node/compat.mjs";
import { createClient } from "../src/node/client.mjs";
import { validateReport } from "../benchmarks/sdk-benchmark.mjs";

const generated = new URL("../generated/", import.meta.url);
const fixture = JSON.parse(await readFile(new URL("fixtures.json", generated)));
const metadata = JSON.parse(await readFile(new URL("benchmark.json", generated)));
const definition = metadata.definitions.small;
const certs = fixture.signing.certs.map((cert) => Buffer.from(cert));
const pem = Buffer.from(certs.map((cert) => `-----BEGIN CERTIFICATE-----\n${cert.toString("base64")
  .match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`).join(""));
const config = { alg: "es256", certs: [pem], reserveSize: 10000, directCoseHandling: false };
const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", generated)),
  { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const signing = async (bytes) => {
  assert.ok(Buffer.isBuffer(bytes), "callback must receive a Buffer");
  return Buffer.from(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, bytes));
};
// The reference SDK owns GC-finalized native handles with no dispose method.
test.after(() => globalThis.gc());

// Adapted scenarios: upstream Reader.spec.ts buffer/path/sniff/null/accessors
// and Builder.spec.ts callback-to-buffer/file; baseline definitions stay narrow.
async function clientScenarios(sdk, folder) {
  const { Reader, Builder, CallbackSigner, Context } = sdk;
  const context = new Context(metadata.settings);
  const signed = await readFile(new URL("benchmark-small.jpg", generated));
  const source = await readFile(new URL("benchmark-small-source.jpg", generated));
  const path = join(folder, "no-extension");
  await writeFile(path, signed);
  const readers = [];
  for (const asset of [
    { buffer: signed, mimeType: "image/jpeg" }, { buffer: signed },
    { path }, { buffer: signed, mimeType: "jpeg" },
  ]) {
    const reader = await Reader.fromAsset(asset, context);
    assert.ok(reader);
    const json = reader.json();
    validateReport(json, definition);
    assert.equal(reader.activeLabel(), json.active_manifest);
    assert.deepEqual(reader.getActive(), json.manifests[json.active_manifest]);
    json.manifests[json.active_manifest].title = "caller mutation";
    const active = reader.getActive();
    active.title = "another caller mutation";
    assert.equal(reader.getActive().title, definition.title);
    readers.push(reader.json());
  }
  for (const report of readers) assert.deepEqual(report, readers[0]);
  await writeFile(path, source);
  assert.equal(await Reader.fromAsset({ path }, context), null);
  assert.equal(await Reader.fromAsset({ buffer: source, mimeType: "image/jpeg" }, context), null);
  const callbackSigner = CallbackSigner.newSigner(config, signing);
  assert.equal(callbackSigner.alg(), "es256");
  assert.equal(callbackSigner.reserveSize(), 10000);
  assert.equal(callbackSigner.directCoseHandling(), false);
  assert.equal(callbackSigner.timeAuthorityUrl(), undefined);
  assert.deepEqual(callbackSigner.certs(), Array.from(pem));
  assert.equal((await callbackSigner.sign(Buffer.from("callback probe"))).length, 64);
  const outputs = [];
  for (const input of [{ path, mimeType: "image/jpeg" }, { buffer: source, mimeType: "image/jpeg" }]) {
    for (const file of [false, true]) {
      const settings = structuredClone(metadata.settings);
      const copy = structuredClone(definition);
      const builder = await Builder.withJsonAsync(copy, new Context(settings));
      copy.title = "mutated after construction";
      const outputPath = join(folder, `output-${outputs.length}.jpg`);
      const output = file ? { path: outputPath } : { buffer: null };
      let calls = 0;
      const signer = CallbackSigner.newSigner(config, async (bytes) => { calls++; return signing(bytes) });
      const manifest = await builder.signAsync(signer, input, output);
      assert.equal(calls, 1);
      assert.ok(Buffer.isBuffer(manifest) && manifest.length > 0);
      if (!file) {
        assert.ok(Buffer.isBuffer(output.buffer) && output.buffer.length > source.length);
        await writeFile(outputPath, output.buffer);
      } else assert.equal("buffer" in output, false);
      validateReport((await Reader.fromAsset({ path: outputPath }, context)).json(), definition);
      outputs.push(outputPath);
    }
  }
  const changed = Buffer.from(signed);
  changed[changed.length - 1] ^= 1;
  assert.equal((await Reader.fromAsset({ buffer: changed, mimeType: "image/jpeg" }, context))
    .json().validation_state, "Invalid");
  await assert.rejects(Reader.fromAsset({ path: join(folder, "missing.jpg") }, context));
  await assert.rejects(Reader.fromAsset({ buffer: Buffer.from("not jpeg"), mimeType: "image/jpeg" }, context));
  const failedOutput = { buffer: null };
  const builder = await Builder.withJsonAsync(definition, context);
  await assert.rejects(builder.signAsync(CallbackSigner.newSigner(config,
    async () => { throw new Error("application signer failed") }),
  { buffer: source, mimeType: "image/jpeg" }, failedOutput));
  assert.equal(failedOutput.buffer, null);
  // A fresh operation must remain usable after a rejected callback.
  validateReport((await Reader.fromAsset({ buffer: signed }, context)).json(), definition);
  return outputs;
}

test("same client scenarios pass through existing SDK and Worker compatibility facade", { timeout: 60000 }, async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-compat-"));
  const compat = createNodeCompat();
  try {
    const outputs = [];
    for (const [name, sdk] of [["existing", existing], ["compat", compat]]) {
      const directory = join(folder, name);
      await mkdir(directory);
      outputs.push(...await clientScenarios(sdk, directory));
    }
    for (const path of outputs)
      for (const sdk of [existing, compat])
        validateReport((await sdk.Reader.fromAsset({ path }, new sdk.Context(metadata.settings))).json(), definition);
  } finally { await compat.dispose(); await rm(folder, { recursive: true }) }
});

test("facade rejects unsupported binding options rather than promising full parity", async () => {
  const sdk = createNodeCompat();
  try {
    const source = { buffer: await readFile(new URL("benchmark-small-source.jpg", generated)) };
    for (const settings of [
      { verify: { ocspFetch: true } }, { verify: { verifyAfterReading: false } },
      { trust: { userAnchors: ["not PEM text"] } }, { core: {} },
    ]) await assert.rejects(sdk.Reader.fromAsset(source, new sdk.Context(settings)), /unsupported|inline PEM/);
    await assert.rejects(sdk.Reader.fromAsset({ ...source, mimeType: "image/png" }), /JPEG/);
    await assert.rejects(sdk.Reader.fromAsset({ ...source, path: "ambiguous.jpg" }), /exactly one/);
    await assert.rejects(sdk.Reader.fromAsset({ buffer: new Uint8Array(4) }), /Buffer/);
    for (const change of [{ alg: "ps256" }, { directCoseHandling: true }, { reserveSize: 20000 }, { timeAuthorityUrl: "https://tsa.invalid" }])
      assert.throws(() => sdk.CallbackSigner.newSigner({ ...config, ...change }, signing), /unsupported|requires/);
    assert.throws(() => sdk.CallbackSigner.newSigner({ ...config, certs: [Buffer.from("invalid")] }, signing), /PEM/);
    const builder = await sdk.Builder.withJsonAsync(definition, new sdk.Context(metadata.settings));
    await assert.rejects(builder.signAsync({}, source, { buffer: null }), /CallbackSigner/);
    const signer = sdk.CallbackSigner.newSigner(config, signing);
    for (const destination of [{}, { buffer: null, path: "ambiguous" }, { buffer: 4 }])
      await assert.rejects(builder.signAsync(signer, source, destination), /exactly one|null or Buffer/);
  } finally { await sdk.dispose() }
});

test("facade shares one queued Worker and disposal rejects active/queued calls", async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-compat-dispose-"));
  const sdk = createNodeCompat();
  let release;
  try {
    const input = { path: new URL("benchmark-small-source.jpg", generated).pathname };
    const context = new sdk.Context(metadata.settings);
    const builder = await sdk.Builder.withJsonAsync(definition, context);
    let entered;
    const started = new Promise((resolve) => { entered = resolve });
    const gate = new Promise((resolve) => { release = resolve });
    const output = { path: join(folder, "signed.jpg") };
    const pending = builder.signAsync(sdk.CallbackSigner.newSigner(config, async (bytes) => {
      entered(); await gate; return signing(bytes);
    }), input, output);
    const rejected = assert.rejects(pending, /disposed/);
    await started;
    const queued = assert.rejects(sdk.Reader.fromAsset(input, context), /disposed/);
    await sdk.dispose();
    await Promise.all([rejected, queued]);
    release();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(await readdir(folder), []);
    await assert.rejects(sdk.Reader.fromAsset(input, context), /disposed/);
  } finally { release?.(); await sdk.dispose(); await rm(folder, { recursive: true }) }
});

test("facade queues mixed successful calls and preserves callback errors", async () => {
  const sdk = createNodeCompat();
  let release;
  try {
    const context = new sdk.Context(metadata.settings);
    const input = { buffer: await readFile(new URL("benchmark-small-source.jpg", generated)), mimeType: "image/jpeg" };
    const builder = await sdk.Builder.withJsonAsync(definition, context);
    let entered;
    let secondCalls = 0;
    const started = new Promise((resolve) => { entered = resolve });
    const gate = new Promise((resolve) => { release = resolve });
    const firstOutput = { buffer: null };
    const first = builder.signAsync(sdk.CallbackSigner.newSigner(config, async (bytes) => {
      entered(); await gate; return signing(bytes);
    }), input, firstOutput);
    await started;
    const secondOutput = { buffer: null };
    const second = builder.signAsync(sdk.CallbackSigner.newSigner(config, async (bytes) => {
      secondCalls++; return signing(bytes);
    }), input, secondOutput);
    const read = sdk.Reader.fromAsset({ path: new URL("benchmark-small.jpg", generated).pathname }, context);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(secondCalls, 0);
    release();
    await Promise.all([first, second]);
    validateReport((await read).json(), definition);
    assert.equal(secondCalls, 1);
    for (const output of [firstOutput, secondOutput])
      validateReport((await sdk.Reader.fromAsset(output, context)).json(), definition);
    const output = { buffer: Buffer.from("unchanged destination") };
    await assert.rejects(builder.signAsync(sdk.CallbackSigner.newSigner(config,
      async () => { throw new TypeError("typed callback failure") }), input, output),
    (error) => error.name === "TypeError" && error.message === "typed callback failure");
    assert.equal(output.buffer.toString(), "unchanged destination");
  } finally { release?.(); await sdk.dispose() }
});

test("facade preserves the raw Worker report without filling Rust reporting gaps", async () => {
  const sdk = createNodeCompat();
  const raw = createClient();
  try {
    const bytes = await readFile(new URL("benchmark-small.jpg", generated));
    const facade = await sdk.Reader.fromAsset({ buffer: bytes }, new sdk.Context(metadata.settings));
    const direct = await raw.read(bytes, { settings: fixture.settings });
    assert.deepEqual(facade.json(), direct.report);
  } finally { await sdk.dispose(); await raw.dispose() }
});
