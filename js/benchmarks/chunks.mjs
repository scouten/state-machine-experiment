// Experimental compile-time sweep. No production source or public API is changed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { cpus, platform, release, arch } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const base = "a4469a6";
const output = resolve(root, "js/results/chunks");
const mirror = resolve(output, "source");
const target = resolve(output, "target");
const run = (command, args, cwd = root, options = {}) =>
  execFileSync(command, args, { cwd, encoding: "utf8", ...options });
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
mkdirSync(output, { recursive: true });
// This path is owned exclusively by this harness; build products live beside it.
rmSync(mirror, { recursive: true, force: true });
mkdirSync(mirror);
const archive = resolve(output, "baseline.tar");
run("git", ["archive", "-o", archive, base]);
run("tar", ["-xf", archive, "-C", mirror]);
rmSync(archive);
const policies = [
  ["contentauth-c2pa-reader/src/hash_stream.rs", "const CHUNK_SIZE: u64 = 64 * 1024;", "hash"],
  ["contentauth-c2pa-builder/src/hash_stream.rs", "const CHUNK_SIZE: u64 = 64 * 1024;", "hash"],
  ["contentauth-c2pa-file-builder/src/session.rs", "const COPY_CHUNK_LEN: u64 = 1 << 20;", "copy"],
].map(([path, original, key]) => {
  const text = readFileSync(resolve(mirror, path), "utf8");
  assert.equal(text.split(original).length, 2, `private policy moved: ${path}`);
  return { path, original, key, text };
});
const variants = [
  { name: "baseline", hash: 65536, copy: 1048576 },
  { name: "hash16", hash: 16384, copy: 1048576 },
  { name: "hash256", hash: 262144, copy: 1048576 },
  { name: "hash1024", hash: 1048576, copy: 1048576 },
  { name: "copy64", hash: 65536, copy: 65536 },
  { name: "copy4096", hash: 65536, copy: 4194304 },
  { name: "baseline-repeat", hash: 65536, copy: 1048576 },
];
const provenance = {
  base: run("git", ["rev-parse", `${base}^{commit}`]).trim(),
  harness: Object.fromEntries(["chunks.mjs", "chunks-runner.mjs"].map((name) =>
    [name, hash(readFileSync(resolve(root, "js/benchmarks", name)))])),
  node: process.version, rust: run("rustc", ["--version"]).trim(),
  os: `${platform()} ${release()} ${arch()}`, cpu: cpus()[0].model,
  logicalCpus: cpus().length, started: new Date().toISOString(),
  samples: Number(process.env.CHUNK_SAMPLES ?? 5),
};
assert.ok(Number.isSafeInteger(provenance.samples) && provenance.samples > 0);
const results = [];
for (const variant of variants) {
  console.log(`Building ${variant.name}: hash=${variant.hash}, copy=${variant.copy}`);
  for (const policy of policies) {
    const replacement = policy.original.replace(/= .*;/, `= ${variant[policy.key]};`);
    writeFileSync(resolve(mirror, policy.path), policy.text.replace(policy.original, replacement));
  }
  const env = { ...process.env, CARGO_TARGET_DIR: target };
  for (const addon of ["c2pa-node-compat-addon", "c2pa-node-sign-addon"]) {
    run("npm", ["run", "build"], resolve(mirror, addon), { env, stdio: "inherit" });
  }
  // A fresh process per build prevents Node's native-module cache hiding a variant.
  const result = JSON.parse(run(process.execPath, [
    resolve(root, "js/benchmarks/chunks-runner.mjs"), mirror, output,
    variant.name, String(provenance.samples),
  ]));
  result.variant = variant;
  result.policies = Object.fromEntries(policies.map(({ path }) =>
    [path, hash(readFileSync(resolve(mirror, path)))]));
  result.addons = Object.fromEntries(["c2pa-node-compat-addon", "c2pa-node-sign-addon"].map((path) =>
    [path, hash(readFileSync(resolve(mirror, path, "index.node")))]));
  results.push(result);
  writeFileSync(resolve(output, "evidence.json"), JSON.stringify({ provenance, results }, null, 2) + "\n");
}
provenance.locks = Object.fromEntries(["c2pa-node-compat-addon", "c2pa-node-sign-addon"].map((path) =>
  [path, hash(readFileSync(resolve(mirror, path, "Cargo.lock")))]));
provenance.finished = new Date().toISOString();
writeFileSync(resolve(output, "evidence.json"), JSON.stringify({ provenance, results }, null, 2) + "\n");
console.log(`Evidence: ${resolve(output, "evidence.json")}`);
