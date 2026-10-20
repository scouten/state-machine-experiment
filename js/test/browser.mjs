// Runs the shared read/signing contracts and the boundary comparison in
// Chromium, Firefox and WebKit against a loopback-only static server, loading
// the real Wasm build. Run via `npm run test:browser`.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, sep } from "node:path";
import { chromium, firefox, webkit } from "playwright";
import { fingerprints } from "./evidence.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const server = createServer(async (request, response) => {
  try {
    const name = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    if (name === "/") {
      response.setHeader("Content-Type", "text/html");
      response.end("<!doctype html><title>Shared Worker proof</title>");
      return;
    }
    const path = resolve(root, `.${name}`);
    if (!path.startsWith(root.endsWith(sep) ? root : root + sep)) {
      response.writeHead(403).end();
      return;
    }
    response.setHeader("Content-Type", path.endsWith(".wasm") ? "application/wasm" :
      path.endsWith(".mjs") || path.endsWith(".js") ? "text/javascript" : "application/octet-stream");
    response.end(await readFile(path));
  } catch (error) {
    if (error.code !== "ENOENT") console.error(error);
    response.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
try {
  assert.equal((await fetch(origin)).status, 200);
  for (const [name, engine] of Object.entries({ chromium, firefox, webkit })) {
    const browser = await engine.launch({ headless: true });
    try {
      const page = await browser.newPage();
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(origin);
      const result = await page.evaluate(async () => {
        const { createClient } = await import("/src/browser/client.mjs");
        const { contract } = await import("/test/contract.mjs");
        const { signingContract } = await import("/test/signing.mjs");
        const { boundaryComparison } = await import("/benchmarks/boundary.mjs");
        const fixture = await (await fetch("/generated/fixtures.json")).json();
        const load = async (name) => new Uint8Array(await (await fetch(`/generated/${name}.jpg`)).arrayBuffer());
        const pkcs8 = await (await fetch("/generated/test-signer.pk8")).arrayBuffer();
        const small = await load("small");
        const large = await load("large");
        const transports = {};
        for (const transport of ["json", "binary"]) {
          const create = transport === "binary" ? () => createClient() : () => createClient({ transport });
          const signing = await signingContract(create, fixture, pkcs8);
          transports[transport] = { ...(await contract(create, small, large, fixture)), signing };
        }
        const comparison = await boundaryComparison(createClient, fixture, pkcs8);
        return { ...transports.binary, transports, comparison,
          userAgent: navigator.userAgent };
      });
      assert.deepEqual(errors, [], `${name}: unhandled application error`);
      await mkdir(new URL("../results/", import.meta.url), { recursive: true });
      await writeFile(new URL(`../results/${name}.json`, import.meta.url),
        JSON.stringify({ measuredAt: new Date().toISOString(), fingerprints: await fingerprints(), ...result }, null, 2));
      console.log(`${name}: all ${result.checks.length} shared contract checks pass`);
      console.log(`${name}: all ${result.signing.checks.length} shared signing checks pass`);
      console.log(`${name}: both JSON/binary contracts pass; ${result.comparison.samples.length} paired boundary samples validated`);
    } finally { await browser.close() }
  }
} finally { await new Promise((resolve) => server.close(resolve)) }
