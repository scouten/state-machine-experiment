import assert from "node:assert/strict";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import test from "node:test";
import { Client } from "../shared/client.mjs";
import { createClient } from "../node/client.mjs";
import { contract } from "./contract.mjs";
import { fingerprints } from "./evidence.mjs";

test("Node Worker + Neon runs shared contract end to end", async () => {
  const folder = new URL("../generated/", import.meta.url);
  const fixture = JSON.parse(await readFile(new URL("fixtures.json", folder), "utf8"));
  const result = await contract(createClient, await readFile(new URL("small.jpg", folder)),
    await readFile(new URL("large.jpg", folder)), fixture);
  await mkdir(new URL("../results/", import.meta.url), { recursive: true });
  await writeFile(new URL("../results/node.json", import.meta.url),
    JSON.stringify({ measuredAt: new Date().toISOString(), node: process.version,
      platform: process.platform, arch: process.arch, fingerprints: await fingerprints(),
      inputs: fixture.files, ...result }, null, 2));
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
