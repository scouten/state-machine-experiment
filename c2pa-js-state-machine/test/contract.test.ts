import { strict as assert } from "node:assert";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { assertFreshEvidence, extractTests, loadInventory, parityReport, root } from "../scripts/contract.ts";

test("inventory retains suite names, skip/todo, parameterized and dynamic declarations", () => {
  const cases = extractTests(`
    describe("reader", () => {
      test("plain", () => {});
      it.skip("skipped", () => {});
      test.todo("pending");
      test.each([1, 2])("item %s", () => {});
      for (const name of ["a", "b"]) it(name, () => {});
    });
  `, "packages/c2pa-web/test.spec.ts");
  assert.equal(cases.length, 5);
  assert.equal(cases[0].fullName, "reader plain");
  assert.equal(cases[1].sourceMode, "skip");
  assert.equal(cases[2].sourceMode, "todo");
  assert.equal(cases[2].sourceMode, "todo");
  assert.equal(cases[3].parameterized, true);
  assert.equal(cases[4].parameterized, true);
});

test("suite-level skips and pending declarations stay inventoried", () => {
  const cases = extractTests(`
    describe.skip("inactive", () => { it("child", () => {}); });
    it("no callback");
  `, "packages/c2pa-node/contract.spec.ts");
  assert.equal(cases.length, 2);
  assert.equal(cases[0].sourceMode, "skip");
  assert.equal(cases[1].sourceMode, "todo");
});

test("timeout and options arguments cannot hide tests or suite context", () => {
  const cases = extractTests(`
    describe("timeouts", () => { it("slow", async () => {}, 30000); }, {});
  `, "packages/c2pa-node/timeouts.spec.ts");
  assert.equal(cases.length, 1);
  assert.equal(cases[0].fullName, "timeouts slow");
  assert.equal(cases[0].sourceMode, "normal");
});

test("every frozen test remains in the denominator even with no runner", () => {
  const inventory = loadInventory();
  const report = parityReport(inventory);
  assert.ok(report.denominator > 0);
  assert.equal(report.denominator, inventory.tests.length);
  assert.equal(report.legacy.notRun, report.denominator);
  assert.equal(report.stateMachine.unported, report.denominator);
  assert.equal(report.fullParity, false);
});

test("legacy passes never become state-machine passes", () => {
  const inventory = loadInventory();
  const report = parityReport(inventory, [{ id: inventory.tests[0].id, status: "passed" }]);
  assert.equal(report.legacy.passed, 1);
  assert.equal(report.stateMachine.passed, 0);
  assert.equal(report.stateMachine.unported, inventory.tests.length);
  assert.equal(report.fullParity, false);
});

test("unknown, duplicate and empty evidence fails closed", () => {
  const inventory = loadInventory();
  const observation = { id: inventory.tests[0].id, status: "passed" as const };
  assert.throws(() => parityReport(inventory, [{ ...observation, id: "unknown" }]));
  assert.throws(() => parityReport(inventory, [observation, observation]));
  assert.throws(() => parityReport({ ...inventory, tests: [] }));
  const parameterized = inventory.tests.find((test) => test.parameterized);
  assert.ok(parameterized);
  assert.throws(() => parityReport(inventory, [{ ...observation, id: parameterized.id }]));
});

test("public types are frozen alongside all four package surfaces", () => {
  const inventory = loadInventory();
  for (const name of inventory.upstream.packages)
    assert.ok(inventory.surfaces.some((surface) => surface.file.startsWith(`packages/${name}/`)), name);
  assert.ok(inventory.publishedTypes.some((file) => file.file.startsWith("@contentauth/c2pa-types/")));
});

test("unknown backend selection fails before running legacy", () => {
  const result = spawnSync(process.execPath,
    ["--import", "tsx", "scripts/oracle.ts", "--backend", "invalid"],
    { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown contract backend.*legacy fallback is forbidden/);
});

test("full-parity CLI fails while cases remain unported", () => {
  const result = spawnSync(process.execPath,
    ["--import", "tsx", "scripts/report.ts", "--require-parity"],
    { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 1);
  if (result.stdout.trim()) assert.equal(JSON.parse(result.stdout).fullParity, false);
  else assert.match(result.stderr, /Stale oracle evidence/);
});

test("state-machine evidence is independent and cannot remove remaining contracts", () => {
  const inventory = loadInventory();
  const result = parityReport(inventory, [], [{ id: inventory.tests[0].id, status: "passed" }]);
  assert.equal(result.stateMachine.passed, 1);
  assert.equal(result.stateMachine.unported, inventory.tests.length - 1);
  assert.equal(result.legacy.passed, 0);
  assert.equal(result.fullParity, false);
  assert.throws(() => parityReport(inventory, [], [{ id: "unknown", status: "passed" }]));
});

test("changed harness source dependencies or artifacts invalidate browser evidence", () => {
  const fingerprint = { inventorySha256: "source", lockSha256: "dependencies",
    harnessSha256: "harness", artifactsSha256: "wasm" };
  assert.doesNotThrow(() => assertFreshEvidence(fingerprint, fingerprint));
  for (const key of Object.keys(fingerprint) as (keyof typeof fingerprint)[])
    assert.throws(() => assertFreshEvidence({ ...fingerprint, [key]: "changed" }, fingerprint),
      new RegExp(`Stale oracle evidence \\(${key}\\)`));
});
