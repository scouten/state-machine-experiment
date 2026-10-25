// Runs the shared read/signing contracts and the boundary comparison in
// Chromium, Firefox and WebKit against a loopback-only static server, loading
// the real Wasm build. Run via `npm run test:browser`.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir, writeFile, open, unlink } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, sep } from "node:path";
import { chromium, firefox, webkit } from "playwright";
import { fingerprints } from "./evidence.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const rangesOnly = process.argv.includes("--ranges-only");
const sourcePath = resolve(root, "generated/browser-range-source.jpg");
const sourceFile = await open(sourcePath, "w");
try {
  await sourceFile.write(new Uint8Array([255, 216, 255, 217]));
  await sourceFile.truncate(64 * 1024 * 1024);
} finally { await sourceFile.close() }
const server = createServer(async (request, response) => {
  try {
    const name = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    if (name === "/") {
      response.setHeader("Content-Type", "text/html");
      response.end('<!doctype html><title>Shared Worker proof</title><input id="signed" type="file"><input id="source" type="file">');
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
      await page.setInputFiles("#signed", resolve(root, "generated/large.jpg"));
      await page.setInputFiles("#source", sourcePath);
      const result = await page.evaluate(async (rangesOnly) => {
        const { createClient } = await import("/src/browser/client.mjs");
        const { contract } = await import("/test/contract.mjs");
        const { signingContract } = await import("/test/signing.mjs");
        const { boundaryComparison } = await import("/benchmarks/boundary.mjs");
        const { rangeContract } = await import("/test/range-contract.mjs");
        const fixture = await (await fetch("/generated/fixtures.json")).json();
        const load = async (name) => new Uint8Array(await (await fetch(`/generated/${name}.jpg`)).arrayBuffer());
        const pkcs8 = await (await fetch("/generated/test-signer.pk8")).arrayBuffer();
        const small = rangesOnly ? undefined : await load("small");
        const large = rangesOnly ? undefined : await load("large");
        const transports = {};
        for (const transport of rangesOnly ? [] : ["json", "binary"]) {
          const create = transport === "binary" ? () => createClient() : () => createClient({ transport });
          const signing = await signingContract(create, fixture, pkcs8);
          transports[transport] = { ...(await contract(create, small, large, fixture)), signing };
        }
        const comparison = rangesOnly ? undefined : await boundaryComparison(createClient, fixture, pkcs8);
        const signedBlob = await (await fetch("/generated/large.jpg")).blob();
        const block = new Blob([new Uint8Array(1024 * 1024)]);
        const sourceBlob = new Blob([new Uint8Array([255, 216, 255, 217]),
          ...Array(63).fill(block), block.slice(4)]);
        const ranges = {};
        for (const [kind, signed, source] of [
          ["Blob", signedBlob, sourceBlob],
          ["File", document.querySelector("#signed").files[0], document.querySelector("#source").files[0]],
        ]) {
          ranges[kind] = await rangeContract(createClient, signed, source, fixture, pkcs8);
        }
        return { ...transports.binary, transports, comparison, ranges,
          userAgent: navigator.userAgent };
      }, rangesOnly);
      assert.deepEqual(errors, [], `${name}: unhandled application error`);
      await mkdir(new URL("../results/", import.meta.url), { recursive: true });
      await writeFile(new URL(`../results/${rangesOnly ? "ranges-" : ""}${name}.json`, import.meta.url),
        JSON.stringify({ measuredAt: new Date().toISOString(), fingerprints: await fingerprints(), ...result }, null, 2));
      if (!rangesOnly) {
        console.log(`${name}: all ${result.checks.length} shared contract checks pass`);
        console.log(`${name}: all ${result.signing.checks.length} shared signing checks pass`);
        console.log(`${name}: both JSON/binary contracts pass; ${result.comparison.samples.length} paired boundary samples validated`);
      }
      console.log(`${name}: actual Blob/File source I/O ${JSON.stringify(result.ranges)}`);
    } finally { await browser.close() }
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
  await unlink(sourcePath);
}
