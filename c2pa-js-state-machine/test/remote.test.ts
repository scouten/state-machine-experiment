import assert from "node:assert/strict";
import { test } from "node:test";
import { remoteManifestHost } from "../src/remote.ts";

const options = { allowedOrigins: ["https://example.test"], maxBytes: 3, timeoutMs: 1000 };

test("remote host rejects invalid limits and non-origin or insecure allowlist entries", () => {
  for (const maxBytes of [0, -1, 1.5, Infinity]) {
    assert.throws(() => remoteManifestHost({ ...options, maxBytes }));
  }
  for (const timeoutMs of [0, 2_147_483_648, NaN]) {
    assert.throws(() => remoteManifestHost({ ...options, timeoutMs }));
  }
  for (const allowedOrigins of [[], ["http://example.test"], ["https://example.test/path"],
    ["https://user@example.test"], ["data:text/plain,x"]]) {
    assert.throws(() => remoteManifestHost({ ...options, allowedOrigins }));
  }
});

test("remote host policy uses a copied allowlist and rejects unsafe URLs without fetch", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => { calls++; throw new Error("must not fetch") });
  const allowedOrigins = ["https://example.test"];
  const host = remoteManifestHost({ ...options, allowedOrigins });
  allowedOrigins.push("https://denied.test");
  for (const url of ["https://denied.test/store", "https://user@example.test/store",
    "https://example.test/store#fragment", "file:///store", "/relative"]) {
    await assert.rejects(host(url));
  }
  assert.equal(calls, 0);
});

test("remote host enforces streamed size without content-length and returns exact bytes", async (t) => {
  let size = 3;
  let cancelled = false;
  t.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(Uint8Array.of(1, 2));
      controller.enqueue(new Uint8Array(size - 2).fill(3));
      if (size === 3) controller.close();
    },
    cancel() { cancelled = true },
  })));
  const host = remoteManifestHost(options);
  assert.deepEqual(await host("https://example.test/store"), Uint8Array.of(1, 2, 3));
  size = 4;
  await assert.rejects(host("https://example.test/store"), /byte limit/);
  assert.equal(cancelled, true);
});

test("remote host rejects non-success empty and misleading-length responses", async (t) => {
  let response = new Response("error", { status: 503 });
  t.mock.method(globalThis, "fetch", async () => response);
  const host = remoteManifestHost(options);
  await assert.rejects(host("https://example.test/store"), /HTTP status 503/);
  response = new Response(new Uint8Array());
  await assert.rejects(host("https://example.test/store"), /empty/);
  response = new Response(Uint8Array.of(1), { headers: { "Content-Length": "4" } });
  await assert.rejects(host("https://example.test/store"), /byte limit/);
});
