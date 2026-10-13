import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { assertFreshEvidence, buildInventory, extractTests, harnessFingerprint, hash, legacyArtifacts, loadInventory, parityReport, pin, root, stateArtifacts, type Observation } from "./contract.ts";

const inventory = loadInventory();
if (hash(JSON.stringify(buildInventory())) !== hash(JSON.stringify(inventory)))
  throw new Error("Pinned source has changed; rerun inventory:check");
function observations(backend: "legacy" | "state-machine"): Observation[] {
  const evidence = join(root, `results/${backend}-observations.json`);
  if (!existsSync(evidence)) return [];
  const result = JSON.parse(readFileSync(evidence, "utf8")) as {
    inventorySha256: string; lockSha256: string; artifactsSha256: string; harnessSha256: string; observations: Observation[];
  };
  assertFreshEvidence(result, {
    inventorySha256: hash(JSON.stringify(inventory)),
    lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
    harnessSha256: harnessFingerprint(),
    artifactsSha256: hash(JSON.stringify(backend === "legacy" ? legacyArtifacts() : stateArtifacts())),
  });
  return result.observations;
}
const report = parityReport(inventory, observations("legacy"), observations("state-machine"));
const stateEvidence = join(root, "results/state-machine-observations.json");
const m1 = existsSync(stateEvidence) ? JSON.parse(readFileSync(stateEvidence, "utf8")) as {
  backend: string; browsers: string[]; runs: { browser: string; exit: number; outcomes: Observation[] }[];
} : undefined;
if (m1 && (m1.backend !== "state-machine" ||
    JSON.stringify(m1.browsers) !== JSON.stringify(["chromium", "firefox", "webkit"]) ||
    JSON.stringify(m1.runs.map((run) => run.browser)) !== JSON.stringify(m1.browsers)))
  throw new Error("M1 evidence must cover all three required browsers");
if (m1) {
  const required = [
    ...inventory.tests.filter((test) => test.file === "packages/c2pa-web/src/lib/reader.spec.ts" && pin.oracleTests.includes(test.title)),
    ...extractTests(readFileSync(join(root, "browser/m1.spec.ts"), "utf8"), "browser/m1.spec.ts"),
  ].map((test) => test.id);
  for (const run of m1.runs) {
    const ids = run.outcomes.map((outcome) => outcome.id);
    if (ids.length !== required.length || new Set(ids).size !== required.length ||
        !required.every((id) => ids.includes(id)))
      throw new Error(`Missing, duplicate, or unexpected M1 evidence for ${run.browser}`);
  }
}
const milestone = m1 ? {
  browsers: m1.browsers,
  passed: m1.runs.every((run) => run.exit === 0 && run.outcomes.every((o) => o.status === "passed")),
  executions: m1.runs.reduce((count, run) => count + run.outcomes.length, 0),
} : { passed: false, blocker: "M1 browser proof has not run" };
const completeReport = { ...report, m1: milestone };
mkdirSync(join(root, "results"), { recursive: true });
writeFileSync(join(root, "results/parity.json"), JSON.stringify(completeReport, null, 2) + "\n");
console.log(JSON.stringify({
  upstreamCommit: report.upstreamCommit,
  denominator: report.denominator,
  legacy: report.legacy,
  stateMachine: report.stateMachine,
  fullParity: report.fullParity,
  m1: milestone,
}, null, 2));
if (process.argv.includes("--require-parity") && !report.fullParity) process.exitCode = 1;
