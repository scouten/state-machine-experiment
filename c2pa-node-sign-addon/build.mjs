// Copies the compiled cdylib to `index.node`, where `index.mjs` loads it.
//
//   node build.mjs [profile]     profile defaults to "release"
//
// Honors CARGO_TARGET_DIR, which `cargo llvm-cov show-env` sets for the
// coverage build.
import { copyFileSync, existsSync } from "node:fs";

const profile = process.argv[2] ?? "release";
const target = process.env.CARGO_TARGET_DIR ?? "target";
const candidates = [
  `${target}/${profile}/libc2pa_node_sign_addon.so`,
  `${target}/${profile}/libc2pa_node_sign_addon.dylib`,
  `${target}/${profile}/c2pa_node_sign_addon.dll`,
];
const built = candidates.find(existsSync);
if (!built) throw new Error(`no addon found under ${target}/${profile}; run cargo build first`);
copyFileSync(built, "index.node");
console.log(`${built} -> index.node`);
