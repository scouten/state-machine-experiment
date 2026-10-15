import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { hash, root, stateSources } from "./contract.ts";

const repository = dirname(root);
const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"],
  { cwd: repository, encoding: "utf8" })) as { target_directory: string };
execFileSync("cargo", ["build", "-p", "contentauth-c2pa-web-bindings", "--release", "--target", "wasm32-unknown-unknown"],
  { cwd: repository, stdio: "inherit" });
const lock = readFileSync(join(repository, "Cargo.lock"), "utf8");
const version = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
const local = join(root, ".cache/tools/bin/wasm-bindgen");
const executable = existsSync(local) ? local : "wasm-bindgen";
const cli = execFileSync(executable, ["--version"], { encoding: "utf8" }).trim();
if (!version || cli !== `wasm-bindgen ${version}`)
  throw new Error(`CLI/library mismatch: install wasm-bindgen-cli ${version}; found ${cli}`);
const directory = join(root, ".cache/generated");
mkdirSync(directory, { recursive: true });
execFileSync(executable, [
  join(metadata.target_directory, "wasm32-unknown-unknown/release/contentauth_c2pa_web_bindings.wasm"),
  "--target", "web", "--out-dir", directory, "--out-name", "state_machine",
], { stdio: "inherit" });
writeFileSync(join(directory, "build.json"), JSON.stringify({
  wasmBindgen: version,
  sources: stateSources(),
  cargoLockSha256: hash(lock),
}, null, 2) + "\n");
const definition = readFileSync(join(repository, "contentauth-c2pa-sign-baseline/src/definition.rs"), "utf8")
  .match(/BASELINE_DEFINITION: &str = r#"([\s\S]*?)"#;/)?.[1];
if (!definition) throw new Error("Baseline definition was not found");
writeFileSync(join(directory, "fixtures.json"), JSON.stringify({
  definition: JSON.parse(definition) as unknown,
  source: readFileSync(join(repository, "contentauth-c2pa-reader/tests/fixtures/C.jpg")).toString("base64"),
  cert: readFileSync(join(repository, "contentauth-c2pa-builder/tests/fixtures/test-signer.der")).toString("base64"),
  key: readFileSync(join(repository, "contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem"), "utf8"),
}, null, 2) + "\n");
