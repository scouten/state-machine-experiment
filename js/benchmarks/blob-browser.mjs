// Browser driver for the Blob experiment: serves the repository and runs
// blob-web.mjs in each engine, writing fingerprinted results.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { resolve, sep } from "node:path";
import { chromium, firefox, webkit } from "playwright";
import { blobFingerprints } from "../test/evidence.mjs";

const exec = promisify(execFile);
const root = fileURLToPath(new URL("../", import.meta.url));
const server = createServer(async (request, response) => {
  try {
    const name = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    if (name === "/") {
      response.setHeader("Content-Type", "text/html");
      response.end('<!doctype html><input id="source" type="file"><input id="signed" type="file">');
      return;
    }
    const path = resolve(root, `.${name}`);
    if (!path.startsWith(root.endsWith(sep) ? root : root + sep)) { response.writeHead(403).end(); return }
    response.setHeader("Content-Type", path.endsWith(".wasm") ? "application/wasm" :
      /\.(mjs|js)$/.test(path) ? "text/javascript" : "application/octet-stream");
    response.end(await readFile(path));
  } catch (error) {
    if (error.code !== "ENOENT") console.error(error);
    response.writeHead(404).end();
  }
});
async function rss(rootPid) {
  const { stdout } = await exec("ps", ["-axo", "pid=,ppid=,rss="]);
  const rows = stdout.trim().split("\n").map((line) => line.trim().split(/\s+/).map(Number));
  const included = new Set([rootPid]);
  for (let changed = true; changed;) {
    changed = false;
    for (const [pid, parent] of rows)
      if (included.has(parent) && !included.has(pid)) { included.add(pid); changed = true }
  }
  const selected = rows.filter(([pid]) => included.has(pid));
  assert.ok(selected.some(([pid]) => pid === rootPid), "browser process disappeared");
  return selected.reduce((sum, [, , kb]) => sum + kb * 1024, 0);
}
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
try {
  assert.equal((await fetch(`http://127.0.0.1:${server.address().port}`)).status, 200);
  for (const [name, engine] of Object.entries({ chromium, firefox, webkit })) {
    const host = await engine.launchServer({ headless: true });
    const browser = await engine.connect(host.wsEndpoint());
    const results = {};
    try {
      for (const size of ["small", "medium", "large"]) {
        const page = await browser.newPage();
        const errors = [];
        page.on("pageerror", (error) => errors.push(error.message));
        let active = false;
        let peak = 0;
        let count = 0;
        let sampling;
        await page.exposeFunction("memoryCurrent", () => rss(host.process().pid));
        await page.exposeFunction("memoryStart", async () => {
          assert.equal(active, false);
          active = true;
          peak = await rss(host.process().pid);
          count = 1;
          const baseline = peak;
          sampling = (async () => {
            while (active) {
              peak = Math.max(peak, await rss(host.process().pid)); count++;
              await new Promise((resolve) => setTimeout(resolve, 25));
            }
          })();
          return baseline;
        });
        await page.exposeFunction("memoryStop", async () => {
          if (!active) return;
          active = false;
          await sampling;
          peak = Math.max(peak, await rss(host.process().pid)); count++;
          return { peak, samples: count };
        });
        try {
          await page.goto(`http://127.0.0.1:${server.address().port}`);
          for (const [id, suffix] of [["source", "-source"], ["signed", ""]])
            await page.locator(`#${id}`).setInputFiles(resolve(root, `generated/blob-${size}${suffix}.jpg`));
          results[size] = await page.evaluate(async (size) => (await import("/benchmarks/blob-web.mjs")).run(size), size);
          assert.deepEqual(errors, [], "unhandled browser error");
          console.log(`${name} ${size}: ${results[size].samples.length} operations validated`);
        } finally { active = false; await sampling; await page.close() }
      }
      await writeFile(new URL(`../results/blob-${name}.json`, import.meta.url), JSON.stringify({
        measuredAt: new Date().toISOString(),
        memory: "sum of browser process-tree RSS; 25 ms plus ps latency and endpoint; shared pages may be counted more than once; no forced GC",
        memoryCoverage: name === "webkit"
          ? "INCOMPLETE on macOS: WebKit content/GPU/network XPC processes have parent PID 1; descendant RSS is not total browser memory"
          : "browser descendants including content/Worker processes; RSS sum is not unique physical memory",
        wasmMemory: "not separately exposed by public client; included in process RSS",
        provenance: JSON.parse(await readFile(new URL("../generated/existing-sdk/provenance.json", import.meta.url))),
        fingerprints: await blobFingerprints(), results,
      }, null, 2));
    } finally { await browser.close(); await host.close() }
  }
} finally { await new Promise((resolve) => server.close(resolve)) }
