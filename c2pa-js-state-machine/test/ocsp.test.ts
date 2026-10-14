import assert from "node:assert/strict";
import { test } from "node:test";
import { ocspHost } from "../src/ocsp.ts";

const options = { allowedOrigins: ["http://ocsp.example.test"], maxBytes: 3, timeoutMs: 1000 };

test("OCSP host POSTs exact DER with safe fetch policy to explicitly authorized HTTP", async (t) => {
  const request = Uint8Array.of(1, 2);
  t.mock.method(globalThis, "fetch", async (url: URL, init: RequestInit) => {
    assert.equal(url.href, "http://ocsp.example.test/check");
    assert.equal(init.method, "POST");
    assert.deepEqual(init.body, request);
    assert.deepEqual(init.headers, { "Content-Type": "application/ocsp-request", Accept: "application/ocsp-response" });
    assert.equal(init.redirect, "error");
    assert.equal(init.credentials, "omit");
    assert.equal(init.referrerPolicy, "no-referrer");
    return new Response(Uint8Array.of(3, 4, 5));
  });
  assert.deepEqual(await ocspHost(options)("http://ocsp.example.test/check", request), Uint8Array.of(3, 4, 5));
});

test("OCSP host denies unapproved URLs and pre-aborted calls before fetch", async (t) => {
  t.mock.method(globalThis, "fetch", async () => { throw new Error("unexpected fetch") });
  const host = ocspHost(options);
  await assert.rejects(host("http://unapproved.test/check", Uint8Array.of(1)), /denied/);
  const controller = new AbortController();
  controller.abort(new Error("caller cancellation"));
  await assert.rejects(ocspHost({ ...options, signal: controller.signal })(
    "http://ocsp.example.test/check", Uint8Array.of(1)), /caller cancellation/);
});

test("OCSP host shares streaming bounds, HTTP errors and full-body deadline", async (t) => {
  let response = new Response(Uint8Array.of(1, 2, 3, 4));
  t.mock.method(globalThis, "fetch", async (_url: URL, init: RequestInit) => {
    if (response.status === 200 && response.headers.has("x-stall")) {
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(Uint8Array.of(1));
          init.signal?.addEventListener("abort", () => controller.error(init.signal?.reason), { once: true });
        },
      }));
    }
    return response;
  });
  const host = ocspHost({ ...options, timeoutMs: 20 });
  await assert.rejects(host("http://ocsp.example.test/check", Uint8Array.of(1)), /byte limit/);
  response = new Response("error", { status: 503 });
  await assert.rejects(host("http://ocsp.example.test/check", Uint8Array.of(1)), /HTTP status 503/);
  response = new Response("", { headers: { "x-stall": "true" } });
  await assert.rejects(host("http://ocsp.example.test/check", Uint8Array.of(1)), /deadline/);
});
