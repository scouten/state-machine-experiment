// Node host tests: file-backed streams, failure cleanup, close ordering and
// Worker service behaviour, run with `npm test`.
import assert from "node:assert/strict";
import { readFile, mkdir, writeFile, mkdtemp, rm, truncate, readdir, symlink, chmod } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { openAsBlob } from "node:fs";
import test from "node:test";
import { Client, protocol } from "../src/shared/client.mjs";
import { createClient, snapshotNodeAsset } from "../src/node/client.mjs";
import { openSource } from "../src/node/source.mjs";
import { contract } from "./contract.mjs";
import { signingContract } from "./signing.mjs";
import { fingerprints } from "./evidence.mjs";
import { read, source } from "../src/shared/drive.mjs";
import { serve } from "../src/shared/service.mjs";
import { openOutput } from "../src/node/output.mjs";

test("file output supports positioned reads/writes and cleans failed commits", async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-output-"));
  const path = join(folder, "signed.jpg");
  const temporary = join(folder, "temporary");
  try {
    const output = await openOutput({ path, temporary });
    await output.write(0, Buffer.from("12345"));
    await output.write(2, Buffer.from("AB"));
    assert.equal((await output.read(0, 5)).toString(), "12AB5");
    await assert.rejects(output.read(0, 6), /invalid asset range/);
    assert.deepEqual(await output.finish(), { path, outputBytes: 5 });
    await output.close();
    assert.equal((await readFile(path)).toString(), "12AB5");
    const failed = await openOutput({ path: folder, temporary });
    await failed.write(0, Buffer.from("x"));
    await assert.rejects(failed.finish(), /EISDIR|ENOTDIR|EEXIST/);
    await failed.close();
    assert.deepEqual(await readdir(folder), ["signed.jpg"]);
    await writeFile(temporary, "do not truncate");
    await assert.rejects(openOutput({ path, temporary }), /EEXIST/);
    assert.equal((await readFile(temporary)).toString(), "do not truncate");
  } finally { await rm(folder, { recursive: true }) }
});

test("file signing preserves destinations on failure, cleans disposal and reads back Trusted", async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-sign-file-"));
  const fixtureFolder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", fixtureFolder)));
  const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", fixtureFolder)),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signer = { alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, bytes)) };
  const options = { settings: fixture.settings, now: fixture.now };
  const path = join(folder, "signed.jpg");
  const source = new URL("large.jpg", fixtureFolder).pathname;
  const client = createClient();
  try {
    await writeFile(path, "existing destination");
    const before = await readdir(folder);
    for (const definition of ["{bad json", fixture.signing.definition]) {
      await assert.rejects(client.sign({ path: source }, definition,
        { ...signer, sign() { throw new Error("sign failure") } }, { path }), /Definition|JSON|json|sign failure/);
      assert.equal((await readFile(path)).toString(), "existing destination");
      assert.deepEqual(await readdir(folder), before);
    }
    await assert.rejects(client.sign({ path: source }, fixture.signing.definition, signer,
      { path: join(folder, "missing", "signed.jpg") }), /ENOENT/);
    await assert.rejects(client.sign({ path: source }, fixture.signing.definition, signer,
      { path: folder }), /EISDIR|ENOTDIR|EEXIST/);
    assert.deepEqual(await readdir(folder), before);
    const dest = { path: relative(process.cwd(), path) };
    const pending = client.sign({ path: source }, fixture.signing.definition, signer, dest);
    dest.path = "changed-after-call.jpg";
    const result = await pending;
    assert.equal(result.path, path);
    assert.equal(result.asset, undefined);
    assert.equal((await readFile(path)).length, result.outputBytes);
    const buffered = await client.sign({ path: source }, fixture.signing.definition, signer);
    assert.deepEqual(result.stats, buffered.stats);
    assert.deepEqual(result.exclusions, buffered.exclusions);
    assert.equal(result.manifest.length, buffered.manifest.length);
    assert.equal((await client.read({ path }, options)).report.validation_state, "Trusted");
    const byteOutput = join(folder, "bytes.jpg");
    const byteResult = await client.sign(await readFile(source), fixture.signing.definition, signer,
      { path: byteOutput });
    assert.equal(byteResult.asset, undefined);
    assert.equal((await client.read({ path: byteOutput }, options)).report.validation_state, "Trusted");
    await assert.rejects(client.sign({ path: source }, fixture.signing.definition, signer, { path: "" }),
      /destination.path/);
    // Replacement is atomic rather than following/truncating a destination symlink.
    const link = join(folder, "link.jpg");
    await symlink(path, link);
    const original = await readFile(path);
    await client.sign({ path: source }, fixture.signing.definition, signer, { path: link });
    assert.deepEqual(await readFile(path), original);
    // Input and destination may coincide: replacement occurs after all source reads.
    await client.sign({ path }, fixture.signing.definition, signer, { path });
    assert.equal((await client.read({ path }, options)).report.validation_state, "Trusted");
    let entered;
    let release;
    const started = new Promise((resolve) => { entered = resolve });
    const gate = new Promise((resolve) => { release = resolve });
    const saved = await readFile(path);
    const interrupted = client.sign({ path: source }, fixture.signing.definition,
      { ...signer, async sign() { entered(); await gate; return new Uint8Array(64) } }, { path });
    const rejected = assert.rejects(interrupted, /disposed/);
    await started;
    assert.ok((await readdir(folder)).some((name) => name.endsWith(".tmp")));
    await client.dispose();
    release();
    await rejected;
    assert.deepEqual(await readFile(path), saved);
    assert.deepEqual((await readdir(folder)).sort(), ["bytes.jpg", "link.jpg", "signed.jpg"]);
  } finally { await client.dispose(); await rm(folder, { recursive: true }) }
});

test("Worker service closes sources before success/error replies", async () => {
  for (const method of ["read", "build"]) {
    for (const fails of [false, true]) {
      let receive;
      let closed = 0;
      let reply;
      const completed = new Promise((resolve) => { reply = resolve });
      const session = {
        advance() { if (fails) throw new Error("session failure"); return { done: true } },
        finish() { return method === "read" ? null : {} },
        close() {},
      };
      serve({
        onMessage(callback) { receive = callback },
        post(message) { if (!message.ready) { assert.equal(closed, 1); reply(message) } },
      }, { create: () => session, createBuild: () => session },
      async () => ({ length: 0, close: async () => { closed++ } }));
      receive({ protocol, id: 1, method });
      const result = await completed;
      assert.equal(result.ok, !fails);
      if (fails) assert.equal(result.error.message, "session failure");
    }
  }
});

test("disposal retries temporary-file cleanup after a failed unlink", {
  skip: process.platform === "win32" || process.getuid?.() === 0,
}, async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-cleanup-retry-"));
  const client = createClient();
  const fixtureFolder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", fixtureFolder)));
  const path = join(folder, "signed.jpg");
  try {
    await writeFile(path, "existing destination");
    await assert.rejects(client.sign(new Uint8Array([255, 216, 255, 217]),
      fixture.signing.definition, {
        alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
        async sign() {
          await chmod(folder, 0o500);
          throw new Error("signer failed while cleanup is denied");
        },
      }, { path }), /EACCES|EPERM/);
    assert.equal((await readFile(path)).toString(), "existing destination");
    assert.equal((await readdir(folder)).filter((name) => name.endsWith(".tmp")).length, 1);
    await chmod(folder, 0o700);
    await client.dispose();
    assert.deepEqual(await readdir(folder), ["signed.jpg"]);
  } finally {
    await chmod(folder, 0o700);
    await client.dispose();
    await rm(folder, { recursive: true });
  }
});

test("named-pipe sources reject without blocking queued reads and signs", {
  skip: process.platform === "win32", timeout: 10000,
}, async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-fifo-"));
  const path = join(folder, "pipe");
  const client = createClient();
  const fixtureFolder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", fixtureFolder)));
  const signer = { alg: "es256",
    certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
    sign: async () => new Uint8Array(64) };
  try {
    execFileSync("mkfifo", [path]);
    const source = new Uint8Array([255, 216, 255, 217]);
    const invalidRead = assert.rejects(client.read({ path }), /regular file/);
    const validRead = client.read(source);
    const invalidSign = assert.rejects(client.sign({ path }, fixture.signing.definition, signer), /regular file/);
    const validSign = client.sign(source, fixture.signing.definition, signer);
    const [, readResult, , signResult] = await Promise.all([invalidRead, validRead, invalidSign, validSign]);
    assert.equal(readResult.report, null);
    assert.ok(signResult.asset.length > source.length);
  } finally {
    await client.dispose();
    await rm(folder, { recursive: true });
  }
});

test("Node path input snapshots its descriptor, not file contents", () => {
  const asset = { path: "relative.jpg" };
  const snapshot = snapshotNodeAsset(asset);
  asset.path = "changed.jpg";
  assert.equal(snapshot.path, join(process.cwd(), "relative.jpg"));
  for (const path of ["", null, 42]) assert.throws(() => snapshotNodeAsset({ path }), /nonempty string/);
});

test("file source uses positional exact reads and rejects truncation/ranges", async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-source-"));
  const path = join(folder, "input.jpg");
  let input;
  try {
    const bytes = Buffer.alloc(150000, 17);
    bytes[70000] = 42;
    await writeFile(path, bytes);
    input = await openSource({ path });
    assert.equal(input.length, bytes.length);
    const parts = await Promise.all([input.read(70000, 70000), input.read(10, 20)]);
    assert.deepEqual(parts[0], bytes.subarray(70000, 140000));
    assert.deepEqual(parts[1], bytes.subarray(10, 30));
    for (const [start, len] of [[-1, 1], [149999, 2], [0.5, 1], [0, NaN]])
      await assert.rejects(input.read(start, len), /invalid asset range/);
    await truncate(path, 1);
    await assert.rejects(input.read(0, 20), /short asset read/);
    await input.close();
    await assert.rejects(input.read(0, 1), /closed/);
    input = undefined;
    await assert.rejects(openSource({ path: folder }), /regular file/);
    await assert.rejects(openSource({ path: join(folder, "missing") }), /ENOENT/);
  } finally {
    await input?.close();
    await rm(folder, { recursive: true });
  }
});

test("Node paths preserve read/sign reports and recover after source/signer errors", async () => {
  const folder = await mkdtemp(join(tmpdir(), "c2pa-path-contract-"));
  const fixtureFolder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", fixtureFolder)));
  const options = { settings: fixture.settings, now: fixture.now };
  const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", fixtureFolder)),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signer = { alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, bytes)) };
  const client = createClient();
  try {
    for (const name of ["small", "large"]) {
      const path = join(folder, `${name}.jpg`);
      const bytes = await readFile(new URL(`${name}.jpg`, fixtureFolder));
      await writeFile(path, bytes);
      const descriptor = { path: relative(process.cwd(), path) };
      const pending = client.read(descriptor, options);
      descriptor.path = "nonexistent-after-call";
      const result = await pending;
      assert.deepEqual(result, { ...await client.read(bytes, options), workerMs: result.workerMs });
      assert.ok(result.stats.maxReadBytes <= 65536);
      const unsigned = Buffer.alloc(fixture.signing.files[name].sourceBytes);
      unsigned.set([255, 216, 255, 217]);
      await writeFile(path, unsigned);
      assert.equal((await client.read({ path }, options)).report, null);
      const built = await client.sign({ path }, fixture.signing.definition, signer);
      const control = await client.sign(unsigned, fixture.signing.definition, signer);
      assert.deepEqual(built.stats, control.stats);
      assert.deepEqual(built.exclusions, control.exclusions);
      assert.ok(built.stats.maxSourceReadBytes <= 1024 * 1024);
      assert.deepEqual((await client.read(built.asset, options)).report, fixture.files[name].report);
    }
    const path = join(folder, "small.jpg");
    for (const asset of [{ path: join(folder, "missing") }, { path: folder }]) {
      await assert.rejects(client.read(asset), /ENOENT|regular file/);
      await assert.rejects(client.sign(asset, fixture.signing.definition, signer), /ENOENT|regular file/);
    }
    await assert.rejects(client.sign({ path }, "{bad json", signer), /Definition|JSON|json/);
    await assert.rejects(client.sign({ path }, fixture.signing.definition,
      { ...signer, sign() { throw new Error("path signer failed") } }), /path signer failed/);
    const invalid = join(folder, "invalid.jpg");
    await writeFile(invalid, "not a jpeg");
    await assert.rejects(client.read({ path: invalid }), /./);
    const tampered = await readFile(new URL("large.jpg", fixtureFolder));
    tampered[tampered.length - 1] ^= 1;
    await writeFile(path, tampered);
    assert.equal((await client.read({ path }, options)).report.validation_state, "Invalid");
    const results = await Promise.all([
      client.read({ path }, options),
      client.read(await readFile(new URL("small.jpg", fixtureFolder)), options),
    ]);
    assert.equal(results[0].report.validation_state, "Invalid");
    assert.equal(results[1].report.validation_state, "Trusted");
  } finally {
    await client.dispose();
    await rm(folder, { recursive: true });
  }
});

test("disposing a path-backed build rejects active and queued operations", async () => {
  const fixtureFolder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", fixtureFolder)));
  const path = new URL("small.jpg", fixtureFolder).pathname;
  const original = await readFile(path);
  let entered;
  let release;
  const started = new Promise((resolve) => { entered = resolve });
  const gate = new Promise((resolve) => { release = resolve });
  const client = createClient();
  try {
    const build = client.sign({ path }, fixture.signing.definition, {
      alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
      async sign() { entered(); await gate; return new Uint8Array(64) },
    });
    const rejectedBuild = assert.rejects(build, /disposed/);
    await started;
    const rejectedRead = assert.rejects(client.read({ path }), /disposed/);
    await client.dispose();
    await Promise.all([rejectedBuild, rejectedRead]);
    release();
    await new Promise((resolve) => setImmediate(resolve));
    await assert.rejects(client.read({ path }), /disposed/);
    assert.deepEqual(await readFile(path), original);
  } finally { release(); await client.dispose() }
});

test("facade posts immutable Blobs without materializing the source", async () => {
  let receive;
  const messages = [];
  const client = new Client({
    onMessage(callback) { receive = callback }, onError() {}, terminate() {},
    post(message) {
      messages.push(message);
      receive({ protocol, id: message.id, ok: true, value: {} });
    },
  });
  receive({ protocol, ready: true });
  const input = new File([new Uint8Array(1024)], "input.jpg", { type: "image/jpeg" });
  input.arrayBuffer = () => { throw new Error("whole input materialized") };
  try {
    await assert.rejects(client.sign(input, "{}", { alg: "es256", certs: [], sign() {} },
      { path: "not-a-browser-destination.jpg" }), /require the Node client/);
    await client.read(input);
    await client.sign(input, "{}", { alg: "es256", certs: [], sign() {} });
    assert.equal(messages.length, 2);
    for (const message of messages) {
      assert.ok(message.asset instanceof Blob);
      assert.equal(message.asset, input);
      assert.equal(message.asset.size, input.size);
      assert.equal(message.asset.type, input.type);
    }
  } finally { await client.dispose() }
});

test("Node file-backed Blob clone rejection does not crash the Worker", async () => {
  const client = createClient();
  try {
    const input = await openAsBlob(new URL("../generated/small.jpg", import.meta.url));
    await assert.rejects(client.read(input), /not cloneable/);
    const fixture = JSON.parse(await readFile(new URL("../generated/fixtures.json", import.meta.url)));
    const result = await client.read(await readFile(new URL("../generated/small.jpg", import.meta.url)),
      { settings: fixture.settings, now: fixture.now });
    assert.equal(result.report.validation_state, "Trusted");
  } finally { await client.dispose() }
});

test("Blob host reads only requested slices and closes sessions on source errors", async () => {
  const requested = [];
  const blob = new Blob([new Uint8Array(1024 * 1024)]);
  const originalSlice = blob.slice.bind(blob);
  blob.arrayBuffer = () => { throw new Error("whole input materialized") };
  blob.slice = (start, end) => {
    requested.push([start, end]);
    return originalSlice(start, end);
  };
  let closed = 0;
  let step = 0;
  const replies = [];
  const adapter = {
    create() {
      return {
        advance() {
          return step++ === 0 ? { requests: [
            { id: 1, kind: "length" },
            { id: 2, kind: "read", start: 123, len: 65536 },
          ] } : { done: true };
        },
        fulfill(...args) { replies.push(args) },
        finish() { return null },
        close() { closed++ },
      };
    },
  };
  const result = await read(adapter, source(blob), undefined, 0);
  assert.deepEqual(requested, [[123, 123 + 65536]]);
  assert.deepEqual(replies[0], [1, "length", blob.size]);
  assert.equal(replies[1][2].length, 65536);
  assert.equal(result.stats.maxReadBytes, 65536);
  assert.equal(closed, 1);
  for (const mode of ["failure", "short", "range"]) {
    step = 0;
    blob.slice = () => {
      if (mode === "failure") return { arrayBuffer: async () => { throw new Error("source unavailable") } };
      return new Blob([]);
    };
    const input = mode === "range" ? new Blob([]) : blob;
    await assert.rejects(read(adapter, source(input), undefined, 0),
      mode === "failure" ? /source unavailable/ : mode === "short" ? /short asset read/ : /invalid asset range/);
  }
  assert.equal(closed, 4);
});

test("Node Worker + Neon runs shared read/signing contracts end to end", async () => {
  const folder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder), "utf8"));
  const result = await contract(createClient, await readFile(new URL("small.jpg", folder)),
    await readFile(new URL("large.jpg", folder)), fixture);
  const signing = await signingContract(createClient, fixture, await readFile(new URL("test-signer.pk8", folder)));
  await mkdir(new URL("../results/", import.meta.url), { recursive: true });
  await writeFile(new URL("../results/node.json", import.meta.url),
    JSON.stringify({ measuredAt: new Date().toISOString(), node: process.version,
      platform: process.platform, arch: process.arch, fingerprints: await fingerprints(),
      inputs: fixture.files, ...result, signing }, null, 2));
});

test("disposed signer callbacks never post late success or failure", async () => {
  for (const fails of [false, true]) {
    let receive;
    let release;
    let entered;
    const started = new Promise((resolve) => { entered = resolve });
    const gate = new Promise((resolve) => { release = resolve });
    const messages = [];
    const client = new Client({
      onMessage(callback) { receive = callback }, onError() {},
      terminate() {}, post(message) { messages.push(message) },
    });
    receive({ protocol, ready: true });
    const result = client.sign(new Uint8Array(4), "{}", {
      alg: "es256", certs: [],
      async sign() {
        entered();
        await gate;
        if (fails) throw new Error("late failure");
        return new Uint8Array(64);
      },
    });
    await new Promise((resolve) => setImmediate(resolve));
    const command = messages[0];
    receive({ protocol, method: "sign", id: command.id, requestId: 12,
      alg: "es256", data: new Uint8Array(4) });
    await started;
    const rejected = assert.rejects(result, /disposed/);
    await client.dispose();
    await rejected;
    release();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(messages.length, 1, "late callback posted to a disposed Worker");
  }
});

test("signer callback post failure rejects all pending operations", async () => {
  let receive;
  let stopped = false;
  let command;
  const client = new Client({
    onMessage(callback) { receive = callback }, onError() {},
    terminate() { stopped = true },
    post(message) {
      if (message.method === "signReply") throw new Error("callback transport failed");
      if (message.method === "build") command = message;
    },
  });
  receive({ protocol, ready: true });
  const result = client.sign(new Uint8Array(4), "{}", {
    alg: "es256", certs: [], sign: async () => new Uint8Array(64),
  });
  const rejected = assert.rejects(result, /callback transport failed/);
  const queued = assert.rejects(client.read(new Uint8Array(4)), /callback transport failed/);
  await new Promise((resolve) => setImmediate(resolve));
  receive({ protocol, method: "sign", id: command.id, requestId: 12,
    alg: "es256", data: new Uint8Array(4) });
  await Promise.all([rejected, queued]);
  assert.equal(stopped, true);
  await assert.rejects(client.read(new Uint8Array(4)), /callback transport failed/);
  await client.dispose();
});

test("shared facade propagates startup/crash failure and disposes pending calls", async () => {
  let fail;
  let stopped = 0;
  const client = new Client({
    onMessage() {}, onError(callback) { fail = callback },
    terminate() { stopped++ }, post() {},
  });
  const pending = client.read(new Uint8Array(4));
  fail(new Error("native Worker failed"));
  await assert.rejects(pending, /native Worker failed/);
  await assert.rejects(client.read(new Uint8Array(4)), /native Worker failed/);
  await client.dispose();
  assert.ok(stopped > 0);
});
