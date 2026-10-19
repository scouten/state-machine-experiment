import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, sep } from "node:path";
import { chromium, firefox, webkit } from "playwright";
import { sdkFingerprints } from "../test/evidence.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
await mkdir(new URL("../results/", import.meta.url), { recursive: true });
const server = createServer(async (request, response) => {
  try {
    const name = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    if (name === "/") {
      response.setHeader("Content-Type", "text/html");
      response.end("<!doctype html><title>SDK comparison</title>");
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
try {
  const provenance = JSON.parse(await readFile(new URL("../generated/existing-sdk/provenance.json", import.meta.url)));
  for (const [name, engine] of Object.entries({ chromium, firefox, webkit })) {
    const browser = await engine.launch({ headless: true });
    try {
      const page = await browser.newPage();
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      const result = await page.evaluate(async () => (await import("/benchmarks/sdk-web.mjs")).run());
      assert.deepEqual(errors, [], `${name}: unhandled application error`);
      await writeFile(new URL(`../results/sdk-${name}.json`, import.meta.url),
        JSON.stringify({ measuredAt: new Date().toISOString(), provenance, fingerprints: await sdkFingerprints(), ...result }, null, 2));
      console.log(`${name}: ${result.samples.length} SDK measurements; all sign outputs cross-validated`);
    } finally { await browser.close() }
  }
} finally { await new Promise((resolve) => server.close(resolve)) }
