import { build } from "../../../c2pa-js/node_modules/vite/dist/node/index.js";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const sdkRoot = fileURLToPath(new URL("../../../c2pa-js/", import.meta.url));
const output = fileURLToPath(new URL("../generated/existing-sdk/", import.meta.url));
await mkdir(output, { recursive: true });
for (const [name, entry] of [["index", "index"]]) {
  await build({
    configFile: false,
    root: sdkRoot,
    build: { outDir: output, emptyOutDir: false, minify: true,
      lib: { entry: `${sdkRoot}packages/c2pa-web/src/${entry}.ts`, formats: ["es"], fileName: () => `${name}.js` } },
  });
}
await copyFile(`${sdkRoot}packages/c2pa-wasm/pkg/c2pa_bg.wasm`, `${output}/c2pa_bg.wasm`);
const paths = ["packages/c2pa-node/dist/index.node", "packages/c2pa-wasm/pkg/c2pa_bg.wasm",
  "packages/c2pa-wasm/pkg/c2pa.js", "Cargo.lock"];
const hashes = {};
for (const path of paths) hashes[path] = createHash("sha256").update(await readFile(`${sdkRoot}${path}`)).digest("hex");
const versions = {};
for (const name of ["c2pa-node", "c2pa-web"])
  versions[name] = JSON.parse(await readFile(`${sdkRoot}packages/${name}/package.json`)).version;
const provenance = { checkout: sdkRoot, commit: execFileSync("git", ["-C", sdkRoot, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  status: execFileSync("git", ["-C", sdkRoot, "status", "--short"], { encoding: "utf8" }).trim(),
  versions, hashes, note: "Web facade/Worker bundled from checkout source; pre-existing Wasm and Neon artifacts fingerprinted, not rebuilt here." };
await writeFile(`${output}/provenance.json`, JSON.stringify(provenance, null, 2));
