import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build, preview } from "vite";
import { chromium, firefox, webkit } from "playwright";
import { root, hash, harnessFingerprint, stateArtifacts, buildInventory } from "./contract.ts";
import { assertPackageRecord } from "./package-record.ts";

const output = join(root, "results/package.json");
mkdirSync(join(root, "results"), { recursive: true });
rmSync(output, { force: true });
const fingerprint = () => ({
  inventorySha256: hash(JSON.stringify(buildInventory())),
  lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
  harnessSha256: harnessFingerprint(), artifactsSha256: hash(JSON.stringify(stateArtifacts())),
});
const before = fingerprint();
const directory = realpathSync(mkdtempSync(join(tmpdir(), "c2pa-m3-package-")));
const command = (executable: string, args: string[], cwd = directory) =>
  execFileSync(executable, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
try {
  command(process.execPath, ["--import", "tsx", "scripts/build-package.ts"], root);
  const packed = JSON.parse(command("npm", ["pack", join(root, ".cache/package"), "--json", "--ignore-scripts"])) as {
    filename: string; files: { path: string }[];
  }[];
  assert.equal(packed.length, 1);
  assert(packed[0].files.every((file) => file.path === "package.json" || file.path.startsWith("dist/")));
  assert(!packed[0].files.some((file) => /fixtures|\.cache|\.key|test|src\//.test(file.path)));
  const archive = join(directory, packed[0].filename);
  writeFileSync(join(directory, "package.json"), JSON.stringify({ private: true, type: "module" }));
  command("npm", ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", archive]);
  const installed = join(directory, "node_modules/c2pa-js-state-machine");
  const manifest = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.private, true);
  assert.deepEqual(Object.keys(manifest.exports), ["./inline", "./worker", "./worker-entry", "./resources/state-machine.wasm"]);
  assert.equal(hash(readFileSync(join(installed, "dist/state_machine_bg.wasm"))),
    hash(readFileSync(join(root, ".cache/generated/state_machine_bg.wasm"))));
  cpSync(join(root, "browser/package-consumer"), directory, { recursive: true });
  mkdirSync(join(directory, "public"));
  cpSync(join(root, ".cache/generated/fixtures.json"), join(directory, "public/fixtures.json"));
  for (const name of ["C_with_CAWG_data.jpg", "C_with_CAWG_data_thumbnail.jpg"]) {
    cpSync(join(root, ".cache/upstream/packages/c2pa-web/test/assets", name), join(directory, "public", name));
  }
  for (const name of ["generator-icons-v2.jpg", "generator-icon.svg", "ingredient-thumbnails-v2.jpg",
    "ingredient-data-v2.jpg", "ingredient-data.json"]) {
    cpSync(join(root, "browser/fixtures", name), join(directory, "public", name));
  }
  writeFileSync(join(directory, "tsconfig.json"), JSON.stringify({
    compilerOptions: { target: "ES2022", module: "ESNext", moduleResolution: "Bundler", strict: true,
      noEmit: true, resolveJsonModule: true, lib: ["ES2022", "DOM", "WebWorker"], skipLibCheck: true },
    include: ["main.ts", "worker.ts", "assets.d.ts"],
  }));
  command(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--project", join(directory, "tsconfig.json")]);
  await build({ configFile: false, root: directory, logLevel: "warn",
    build: { target: "es2022", assetsInlineLimit: 0 }, worker: { format: "es" } });
  const server = await preview({ configFile: false, root: directory, logLevel: "warn",
    preview: { host: "127.0.0.1", port: 0 } });
  const reports = [];
  try {
    const address = server.httpServer.address();
    assert(address && typeof address !== "string");
    for (const [name, browserType] of Object.entries({ chromium, firefox, webkit })) {
      const browser = await browserType.launch({ headless: true });
      try {
        const paths: string[] = [];
        for (const mode of ["url", "module"]) {
          const page = await browser.newPage();
          await page.goto(`http://127.0.0.1:${address.port}/?mode=${mode}`);
          await page.waitForFunction(() => document.body.dataset.result !== undefined, { timeout: 30_000 });
          const result = JSON.parse(await page.locator("body").getAttribute("data-result") ?? "null");
          assert.deepEqual(result, { ok: true, paths: [`inline-${mode}`, `worker-${mode}`] });
          paths.push(...result.paths);
          await page.close();
        }
        reports.push({ browser: name, ok: true, paths });
        console.log(`Packed Vite consumer: ${name} inline/Worker URL/module read/sign/detached/cross-read passed`);
      } finally { await browser.close() }
    }
  } finally { await new Promise<void>((resolve, reject) => server.httpServer.close((error) => error ? reject(error) : resolve())) }
  assert.deepEqual(fingerprint(), before, "Package proof inputs changed during execution");
  const evidence = {
    schema: 1, measuredAt: new Date().toISOString(), bundler: "vite-6.3.6",
    archiveSha256: hash(readFileSync(archive)), files: packed[0].files.map((file) => file.path),
    ...before, reports,
  };
  assertPackageRecord(evidence, before);
  writeFileSync(output, JSON.stringify(evidence, null, 2) + "\n");
} finally { rmSync(directory, { recursive: true, force: true }) }
