import assert from "node:assert/strict";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import test from "node:test";
import { Client, protocol } from "../src/shared/client.mjs";
import { createClient } from "../src/node/client.mjs";
import { contract } from "./contract.mjs";
import { signingContract } from "./signing.mjs";
import { fingerprints } from "./evidence.mjs";

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

test("a worker pool matches one worker, spreads load, validates size and replaces dead workers", async () => {
  const { ClientPool } = await import("../src/shared/pool.mjs");
  const folder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder)));
  const key = await crypto.subtle.importKey("pkcs8", await readFile(new URL("test-signer.pk8", folder)),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signer = { alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, bytes)) };
  const options = { settings: fixture.settings, now: fixture.now };
  const small = new Uint8Array(await readFile(new URL("small.jpg", folder)));
  for (const workers of [0, 1.5, 65, "2"]) assert.throws(() => createClient({ workers }), RangeError);

  const single = createClient();
  const pool = createClient({ workers: 3 });
  try {
    assert.equal(pool.workers, 3);
    const baseline = await single.sign(small, fixture.signing.definition, signer);
    const signed = await Promise.all(Array.from({ length: 6 }, () => pool.sign(small, fixture.signing.definition, signer)));
    const expected = (await single.read(baseline.asset, options)).report;
    const reads = await Promise.all(signed.map((result) => pool.read(result.asset, options)));
    for (const { report } of reads) assert.equal(report.validation_state, expected.validation_state);
  } finally { await single.dispose(); await pool.dispose() }

  // Dispatch goes to the least-loaded client; a failed one is replaced.
  const calls = [];
  const clients = [];
  const fake = () => {
    const client = { failure: undefined, n: clients.length, dispose: async () => {},
      read: (...args) => { calls.push(client.n); return new Promise((resolve) => { client.finish = resolve }) } };
    clients.push(client);
    return client;
  };
  const fakes = new ClientPool(fake, { workers: 2 });
  const first = fakes.read(1);
  const second = fakes.read(2);
  assert.deepEqual(calls, [0, 1]);
  clients[0].failure = new Error("Worker exited (1)");
  const third = fakes.read(3);
  assert.equal(clients.length, 3, "dead worker replaced");
  assert.deepEqual(calls, [0, 1, 2]);
  for (const client of clients) client.finish?.("ok");
  await Promise.all([first, second, third]);
  await fakes.dispose();
  await assert.rejects(fakes.read(4), /disposed/);
});
