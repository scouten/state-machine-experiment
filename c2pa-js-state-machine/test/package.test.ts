import test from "node:test";
import assert from "node:assert/strict";
import { assertPackageRecord } from "../scripts/package-record.ts";

test("packed consumer evidence requires all browsers, loader paths, exports and fresh inputs", () => {
  const expected = { inventorySha256: "inventory", lockSha256: "lock", harnessSha256: "harness", artifactsSha256: "artifacts" };
  const valid = {
    ...expected, schema: 1, bundler: "vite-6.3.6", archiveSha256: "a".repeat(64),
    files: ["package.json", "dist/index.js", "dist/index.d.ts", "dist/worker.js", "dist/worker.d.ts",
      "dist/worker-entry.js", "dist/worker-entry.d.ts", "dist/state_machine.js", "dist/state_machine_bg.wasm"],
    reports: ["chromium", "firefox", "webkit"].map((browser) => ({
      browser, ok: true, paths: ["inline-url", "worker-url", "inline-module", "worker-module"],
    })),
  };
  assert.doesNotThrow(() => assertPackageRecord(valid, expected));
  for (const mutate of [
    (record: typeof valid) => { record.reports.pop() },
    (record: typeof valid) => { record.reports[1].browser = "chromium" },
    (record: typeof valid) => { record.reports[0].paths.pop() },
    (record: typeof valid) => { record.reports[0].ok = false },
    (record: typeof valid) => { record.files.pop() },
    (record: typeof valid) => { record.files.push("src/index.ts") },
    (record: typeof valid) => { record.harnessSha256 = "stale" },
    (record: typeof valid) => { record.schema = 2 },
  ]) {
    const changed = structuredClone(valid);
    mutate(changed);
    assert.throws(() => assertPackageRecord(changed, expected));
  }
});
