// Node file-path benchmark: compares the existing c2pa-node SDK with the shared
// host reading and signing by path, validating every result before timing it.
import assert from "node:assert/strict";
import { fork, execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { createClient } from "../src/node/client.mjs";
import { validateReport } from "./sdk-benchmark.mjs";
import { fingerprints } from "../test/evidence.mjs";

const folder = new URL("../generated/", import.meta.url);
const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder)));
const metadata = JSON.parse(await readFile(new URL("benchmark.json", folder)));
const definition = metadata.definitions.small;
const options = { settings: fixture.settings, now: fixture.now };
const certs = fixture.signing.certs.map((cert) => Buffer.from(cert));
const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", folder)),
  { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const sign = async (data) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));

async function existingAdapter() {
  const { Reader, Builder, CallbackSigner, Context } =
    await import("../../../c2pa-js/packages/c2pa-node/dist/index.js");
  const context = new Context(metadata.settings);
  const pem = Buffer.from(certs.map((cert) => `-----BEGIN CERTIFICATE-----\n${cert.toString("base64")
    .match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`).join(""));
  return {
    async read(input) {
      const reader = await Reader.fromAsset(input instanceof Uint8Array
        ? { buffer: input, mimeType: "image/jpeg" } : input, context);
      return { report: reader?.json() ?? null };
    },
    async sign(input, signing, output) {
      const builder = await Builder.withJsonAsync(definition, context);
      const destination = output ? { path: output } : { buffer: null };
      const signer = CallbackSigner.newSigner(
        { alg: "es256", certs: [pem], reserveSize: 10000, directCoseHandling: false },
        async (data) => Buffer.from(await signing(data)));
      const manifest = await builder.signAsync(signer, input instanceof Uint8Array
        ? { buffer: input, mimeType: "image/jpeg" } : input, destination);
      return output ? { path: output, outputBytes: (await stat(output)).size, manifest }
        : { asset: destination.buffer, manifest };
    },
    async close() {},
  };
}

function proofAdapter() {
  const client = createClient();
  return {
    read: (input) => client.read(input, options),
    sign: (input, signing, output) => client.sign(input, definition, { alg: "es256", certs, sign: signing },
      output ? { path: output } : undefined),
    close: () => client.dispose(),
  };
}

async function facadeAdapter() {
  const { createNodeCompat } = await import("../src/node/compat.mjs");
  const sdk = createNodeCompat();
  const context = new sdk.Context(metadata.settings);
  return {
    async read(input) {
      const reader = await sdk.Reader.fromAsset(input instanceof Uint8Array
        ? { buffer: input, mimeType: "image/jpeg" } : input, context);
      return { report: reader?.json() ?? null };
    },
    async sign(input, signing, output) {
      const builder = await sdk.Builder.withJsonAsync(definition, context);
      const destination = output ? { path: output } : { buffer: null };
      const pem = Buffer.from(certs.map((cert) => `-----BEGIN CERTIFICATE-----\n${cert.toString("base64")
        .match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`).join(""));
      const signer = sdk.CallbackSigner.newSigner(
        { alg: "es256", certs: [pem], reserveSize: 10000, directCoseHandling: false },
        async (data) => Buffer.from(await signing(data)));
      const manifest = await builder.signAsync(signer, input instanceof Uint8Array
        ? { buffer: input, mimeType: "image/jpeg" } : input, destination);
      return output ? { path: output, outputBytes: (await stat(output)).size, manifest }
        : { asset: destination.buffer, manifest };
    },
    close: () => sdk.dispose(),
  };
}

const send = (message) => new Promise((resolve, reject) =>
  process.send(message, (error) => error ? reject(error) : resolve()));
const nextMessage = () => new Promise((resolve) => process.once("message", resolve));
const usage = () => ({ ...process.memoryUsage(), maxRSS: process.resourceUsage().maxRSS * 1024 });

async function childRun(config) {
  const adapter = config.sdk === "existing" ? await existingAdapter()
    : config.sdk === "facade" ? await facadeAdapter() : proofAdapter();
  let value;
  let input;
  let signerCalls = 0;
  try {
    // Warm just the small read/sign path, not a large asset or a second SDK.
    const warm = config.operation === "read" ? config.warmSigned : config.warmSource;
    const warmInput = config.input === "path" ? { path: warm } : await readFile(warm);
    if (config.operation === "read") await adapter.read(warmInput);
    else await adapter.sign(warmInput, sign, config.destination === "file" ? `${config.output}.warm.jpg` : undefined);
    globalThis.gc();
    const baseline = usage();
    const go = nextMessage();
    await send({ type: "ready", baseline });
    assert.equal((await go).type, "go");
    const started = performance.now();
    input = config.input === "path" ? { path: config.path } : await readFile(config.path);
    value = config.operation === "read" ? await adapter.read(input)
      : await adapter.sign(input, async (bytes) => { signerCalls++; return sign(bytes) },
        config.destination === "file" ? config.output : undefined);
    const totalMs = performance.now() - started;
    const memory = usage();
    if (config.operation === "read") validateReport(value.report, definition);
    else {
      assert.equal(signerCalls, 1);
      assert.ok(value.manifest instanceof Uint8Array && value.manifest.length > 0);
      if (config.destination === "file") {
        assert.equal(value.asset, undefined);
        assert.equal(value.path, config.output);
        assert.ok(value.outputBytes > 0);
      } else assert.ok(value.asset instanceof Uint8Array && value.asset.length > 0);
    }
    if (value.stats) {
      if (config.operation === "read") assert.ok(value.stats.maxReadBytes <= 65536);
      else assert.ok(value.stats.maxSourceReadBytes <= 1024 * 1024);
    }
    const persist = nextMessage();
    await send({ type: "measured", totalMs, memory, signerCalls,
      stats: value.stats, report: value.report, outputBytes: value.outputBytes ?? value.asset?.length,
      manifestBytes: value.manifest?.length });
    assert.equal((await persist).type, "persist");
    if (value.asset) await writeFile(config.output, value.asset);
  } finally {
    value = undefined;
    input = undefined;
    await adapter.close();
  }
}

const exec = promisify(execFile);
async function measure(config) {
  const child = fork(fileURLToPath(import.meta.url), [JSON.stringify(config)],
    { execArgv: ["--expose-gc"], stdio: ["ignore", "inherit", "inherit", "ipc"] });
  let baseline;
  let result;
  let peak = 0;
  let samples = 0;
  let sampling;
  let samplingError;
  let running = false;
  async function sample() {
    const { stdout } = await exec("ps", ["-o", "rss=", "-p", String(child.pid)]);
    const rss = Number(stdout.trim()) * 1024;
    assert.ok(Number.isFinite(rss) && rss > 0, "invalid RSS sample");
    peak = Math.max(peak, rss);
    samples++;
  }
  const completed = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("message", (message) => {
      void (async () => {
        if (message.type === "ready") {
          baseline = message.baseline;
          await sample();
          running = true;
          sampling = (async () => {
            while (running) {
              await sample();
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
          })().catch((error) => { samplingError = error; running = false });
          child.send({ type: "go" });
        } else if (message.type === "measured") {
          running = false;
          await sampling;
          if (samplingError) throw samplingError;
          await sample();
          result = { ...message, baseline, sampledPeakRSS: peak, rssSamples: samples };
          delete result.type;
          child.send({ type: "persist" });
        }
      })().catch(reject);
    });
    child.on("exit", (code, signal) => {
      if (code !== 0 || !result) reject(new Error(`benchmark child failed: ${signal ?? code}`));
      else resolve(result);
    });
  });
  const timeout = setTimeout(() => child.kill(), 60000);
  try { return await completed }
  finally {
    running = false;
    clearTimeout(timeout);
    await sampling;
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}

if (process.argv[2]?.startsWith("{")) {
  await childRun(JSON.parse(process.argv[2]));
  // Native SDK handles are GC-owned. Finalize outside the measured scope.
  globalThis.gc();
  process.disconnect();
} else {
  const fileOutput = process.argv.includes("--file-output");
  const compatibility = process.argv.includes("--compat");
  await mkdir(folder, { recursive: true });
  await mkdir(new URL("../results/", import.meta.url), { recursive: true });
  const scratch = await mkdtemp(fileURLToPath(new URL("path-benchmark-", folder)));
  const proof = proofAdapter();
  const existing = await existingAdapter();
  const samples = [];
  const inputs = {};
  const validations = [];
  try {
    const jpeg = await readFile(new URL("../../../c2pa-js/packages/c2pa-node/tests/fixtures/thumbnail.jpg", import.meta.url));
    for (const [name, size] of [["small", jpeg.length], ["medium", 8 * 1024 * 1024], ["large", 64 * 1024 * 1024]]) {
      const bytes = Buffer.alloc(size);
      bytes.set(jpeg);
      const path = `${scratch}/${name}-source.jpg`;
      const signedPath = `${scratch}/${name}.jpg`;
      await writeFile(path, bytes);
      const signed = await proof.sign({ path }, sign);
      await writeFile(signedPath, signed.asset);
      inputs[name] = {
        sourceBytes: size, signedBytes: signed.asset.length,
        sourceSHA256: createHash("sha256").update(bytes).digest("hex"),
        signedSHA256: createHash("sha256").update(signed.asset).digest("hex"),
      };
    }
    const variants = compatibility ? ["proof", "facade", "existing"].flatMap((sdk) =>
      ["buffer", "file"].map((destination) => ({ sdk, input: "path", destination }))) : fileOutput ? [
      { sdk: "proof", input: "path", destination: "buffer" },
      { sdk: "proof", input: "path", destination: "file" },
      { sdk: "existing", input: "path", destination: "buffer" },
      { sdk: "existing", input: "path", destination: "file" },
    ] : [
      { sdk: "proof", input: "bytes" }, { sdk: "proof", input: "path" },
      { sdk: "existing", input: "bytes" }, { sdk: "existing", input: "path" },
    ];
    for (const name of compatibility ? ["small", "large"] : ["small", "medium", "large"]) {
      const expected = await proof.read({ path: `${scratch}/${name}.jpg` });
      validateReport(expected.report, definition);
      assert.deepEqual((await existing.read({ path: `${scratch}/${name}.jpg` })).report,
        (await existing.read(await readFile(`${scratch}/${name}.jpg`))).report,
        "existing SDK path/Buffer read reports differ");
      for (const reader of [proof, existing])
        assert.equal((await reader.read({ path: `${scratch}/${name}-source.jpg` })).report, null);
      const tamperedPath = `${scratch}/tampered.jpg`;
      const tampered = await readFile(`${scratch}/${name}.jpg`);
      tampered[tampered.length - 1] ^= 1;
      await writeFile(tamperedPath, tampered);
      for (const reader of [proof, existing]) {
        const invalid = (await reader.read({ path: tamperedPath })).report;
        assert.equal(invalid.validation_state, "Invalid");
        const failures = invalid.validation_results?.activeManifest?.failure ?? invalid.validation_status;
        assert.ok(failures.some((status) => status.code === "assertion.dataHash.mismatch"));
      }
      let expectedBuildStats;
      for (const operation of fileOutput ? ["sign"] : ["read", "sign"]) {
        for (let iteration = 0; iteration < 3; iteration++) {
          // Alternate order; every measurement has its own warm process.
          const selected = compatibility && operation === "read"
            ? variants.filter((variant) => variant.destination === "buffer") : variants;
          for (const variant of iteration % 2 ? [...selected].reverse() : selected) {
            const output = `${scratch}/output.jpg`;
            const result = await measure({ ...variant, operation,
              path: `${scratch}/${name}${operation === "read" ? "" : "-source"}.jpg`,
              warmSigned: `${scratch}/small.jpg`, warmSource: `${scratch}/small-source.jpg`, output });
            if (operation === "read" && variant.sdk === "proof") {
              assert.deepEqual(result.report, expected.report);
              assert.deepEqual(result.stats, expected.stats);
            }
            if (operation === "sign") {
              for (const reader of [proof, existing])
                validateReport((await reader.read({ path: output })).report, definition);
              if (variant.sdk === "proof") {
                expectedBuildStats ??= result.stats;
                assert.deepEqual(result.stats, expectedBuildStats);
              }
              assert.equal((await stat(output)).size, result.outputBytes);
            }
            delete result.report;
            samples.push({ name, operation, iteration, ...variant, ...result });
          }
        }
        validations.push(`${name} ${operation}: Trusted reports; every sign cross-validated; proof path/bytes accounting equal; existing path/Buffer reports equal; unsigned null and tamper/hash-mismatch parity`);
        console.log(`Node file-path ${name} ${operation}: isolated measurements validated`);
      }
    }
    const paths = ["benchmarks/path-node.mjs", "benchmarks/sdk-prepare.mjs", "test/evidence.mjs",
      "src/node/compat.mjs", "test/compat.test.mjs", "generated/benchmark.json"];
    const evidence = { ...await fingerprints(), ...Object.fromEntries(await Promise.all(paths.map(async (path) => [
      path, createHash("sha256").update(await readFile(new URL(`../${path}`, import.meta.url))).digest("hex"),
    ]))) };
    const resultName = compatibility ? "compat-node" : fileOutput ? "output-node" : "path-node";
    await writeFile(new URL(`../results/${resultName}.json`, import.meta.url), JSON.stringify({
      measuredAt: new Date().toISOString(), node: process.version, platform: process.platform, arch: process.arch,
      methodology: `fresh process per sample; small matching-operation warmup then GC; 3 alternating-order iterations; file load included for bytes; ${fileOutput || compatibility ? "path source; buffered versus file destination; file completion/rename included" : "buffered sign output for both SDKs"}; ${compatibility ? "raw Worker, compatibility facade and existing SDK; read includes json reporting" : ""}; external ps RSS every 10ms plus ps latency/endpoints; no GC during operation; validation and buffered output persistence outside timing/sampling`,
      provenance: JSON.parse(await readFile(new URL("existing-sdk/provenance.json", folder))),
      fingerprints: evidence, inputs, samples, validations,
    }, null, 2));
    console.log(`${samples.length} measurements passed; results/${resultName}.json`);
  } finally {
    await proof.close();
    await existing.close();
    await rm(scratch, { recursive: true });
  }
  globalThis.gc();
}
