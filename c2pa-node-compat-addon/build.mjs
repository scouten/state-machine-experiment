// Copies the compiled cdylib to `index.node`, where `index.mjs` loads it.
import { copyFileSync, existsSync } from "node:fs";

const candidates = [
  "target/release/libc2pa_node_compat_addon.so",
  "target/release/libc2pa_node_compat_addon.dylib",
  "target/release/c2pa_node_compat_addon.dll",
];
const built = candidates.find(existsSync);
if (!built) throw new Error("run `cargo build --release` first");
copyFileSync(built, "index.node");
console.log(`${built} -> index.node`);
