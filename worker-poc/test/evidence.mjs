import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export async function fingerprints() {
  const paths = ["shared/client.mjs", "shared/service.mjs", "shared/drive.mjs",
    "browser/client.mjs", "browser/entry.mjs", "node/client.mjs", "node/entry.mjs", "node/adapter.mjs",
    "wasm/src/lib.rs", "wasm/Cargo.lock", "test/contract.mjs", "test/fixtures.mjs", "package-lock.json",
    "generated/fixtures.json", "generated/worker_poc_wasm_bg.wasm",
    "../c2pa-node-compat-addon/index.node"];
  return Object.fromEntries(await Promise.all(paths.map(async (path) => [
    path, createHash("sha256").update(await readFile(new URL(`../${path}`, import.meta.url))).digest("hex"),
  ])));
}
