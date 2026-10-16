import assert from "node:assert/strict";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import test from "node:test";
import { Client, protocol } from "../shared/client.mjs";
import { createClient } from "../node/client.mjs";
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
