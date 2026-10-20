import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

/** SHA-256 of every source file a result depends on, recorded beside measurements as provenance. */
export async function fingerprints() {
  const paths = ["src/shared/client.mjs", "src/shared/service.mjs", "src/shared/drive.mjs",
    "src/browser/client.mjs", "src/browser/entry.mjs", "src/node/client.mjs", "src/node/entry.mjs", "src/node/adapter.mjs",
    "../contentauth-c2pa-wasm/src/lib.rs", "../contentauth-c2pa-wasm/src/build.rs",
    "../contentauth-c2pa-wasm/Cargo.toml", "../contentauth-c2pa-wasm/Cargo.lock",
    "test/contract.mjs", "test/signing.mjs", "benchmarks/boundary.mjs", "test/fixtures.mjs", "test/node.test.mjs",
    "test/browser.mjs", "package.json", "package-lock.json",
    "generated/fixtures.json", "generated/contentauth_c2pa_wasm_bg.wasm",
    "../c2pa-node-compat-addon/index.node", "../c2pa-node-sign-addon/index.node"];
  return Object.fromEntries(await Promise.all(paths.map(async (path) => [
    path, createHash("sha256").update(await readFile(new URL(`../${path}`, import.meta.url))).digest("hex"),
  ])));
}

/** `fingerprints` plus the SDK benchmark scripts, fixtures and the pinned existing SDK build. */
export async function sdkFingerprints() {
  const paths = ["benchmarks/sdk-benchmark.mjs", "benchmarks/sdk-prepare.mjs", "benchmarks/sdk-node.mjs",
    "benchmarks/sdk-web.mjs", "benchmarks/sdk-browser.mjs", "test/evidence.mjs",
    "generated/benchmark.json", "generated/benchmark-small-source.jpg",
    "generated/benchmark-large-source.jpg", "generated/benchmark-small.jpg", "generated/benchmark-large.jpg",
    "generated/existing-sdk/index.js", "generated/existing-sdk/c2pa_bg.wasm"];
  return { ...await fingerprints(), ...Object.fromEntries(await Promise.all(paths.map(async (path) => [
    path, createHash("sha256").update(await readFile(new URL(`../${path}`, import.meta.url))).digest("hex"),
  ]))) };
}
