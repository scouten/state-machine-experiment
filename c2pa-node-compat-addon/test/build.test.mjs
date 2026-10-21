import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

for (const addon of ["compat", "sign"]) {
  for (const explicitTarget of [false, true]) {
    test(`${addon} copies the ${explicitTarget ? "explicit target" : "host"} build, never a stale host artifact`, (t) => {
      const dir = mkdtempSync(join(tmpdir(), "c2pa-addon-build-"));
      t.after(() => rmSync(dir, { recursive: true, force: true }));
      const targetDir = join(dir, "cargo output");
      const triple = "x86_64-unknown-linux-gnu";
      const hostDir = join(targetDir, "release");
      const builtDir = explicitTarget ? join(targetDir, triple, "release") : hostDir;
      const library = `libc2pa_node_${addon}_addon.so`;
      mkdirSync(hostDir, { recursive: true });
      writeFileSync(join(hostDir, library), "stale");
      mkdirSync(builtDir, { recursive: true });
      writeFileSync(join(builtDir, library), "expected");
      const script = fileURLToPath(new URL(`../../c2pa-node-${addon}-addon/build.mjs`, import.meta.url));
      const env = { ...process.env, CARGO_TARGET_DIR: targetDir };
      delete env.CARGO_BUILD_TARGET;
      if (explicitTarget) env.CARGO_BUILD_TARGET = triple;
      const result = spawnSync(process.execPath, [script], { cwd: dir, env, encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(join(dir, "index.node"), "utf8"), "expected");
      if (explicitTarget) {
        rmSync(join(builtDir, library));
        const missing = spawnSync(process.execPath, [script], { cwd: dir, env, encoding: "utf8" });
        assert.notEqual(missing.status, 0);
        assert.match(missing.stderr, /no addon found/);
      }
    });
  }
}
