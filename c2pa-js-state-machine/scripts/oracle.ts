import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { assertFreshEvidence, buildInventory, extractTests, harnessFingerprint, hash, legacyArtifacts, loadInventory, pin, root, stateArtifacts, type Observation } from "./contract.ts";

const backend = process.argv.includes("--backend")
  ? process.argv[process.argv.indexOf("--backend") + 1] : "legacy";
if (backend !== "legacy" && backend !== "state-machine")
  throw new Error(`Unknown contract backend: ${backend}; legacy fallback is forbidden`);
const inventory = loadInventory();
if (hash(JSON.stringify(buildInventory())) !== hash(JSON.stringify(inventory)))
  throw new Error("Pinned source differs from inventory; run inventory:check");
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")) as {
  packages: Record<string, { version?: string; integrity?: string }>;
};
const sdk = lock.packages[`node_modules/${pin.legacyPackage}`];
if (sdk?.version !== pin.legacyVersion || sdk.integrity !== pin.legacyIntegrity)
  throw new Error("Legacy SDK version/integrity differs from upstream.json");
const reader = readFileSync(join(root, ".cache/upstream/packages/c2pa-web/src/lib/reader.ts"), "utf8");
if (!/export const MAX_SIZE_IN_BYTES = 10 \*\* 9;/.test(reader))
  throw new Error("Reader size-limit bridge no longer matches pinned source");
const selected = inventory.tests.filter((test) =>
  test.file === "packages/c2pa-web/src/lib/reader.spec.ts" && pin.oracleTests.includes(test.title));
if (selected.length !== pin.oracleTests.length) throw new Error("Oracle selection changed");
const directory = join(root, "results");
mkdirSync(directory, { recursive: true });
const evidence = join(directory, `${backend}-observations.json`);
if (existsSync(evidence)) rmSync(evidence);
const milestone = backend === "state-machine"
  ? extractTests(readFileSync(join(root, "browser/m1.spec.ts"), "utf8"), "browser/m1.spec.ts") : [];
if (backend === "state-machine" && (milestone.length === 0 || milestone.some((t) => t.parameterized || t.sourceMode !== "normal")))
  throw new Error("M1 requires explicit, non-skipped browser tests");
const artifacts = backend === "legacy" ? legacyArtifacts() : stateArtifacts();
const fingerprint = {
  inventorySha256: hash(JSON.stringify(inventory)),
  lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
  artifactsSha256: hash(JSON.stringify(artifacts)),
  harnessSha256: harnessFingerprint(),
};
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const browsers = backend === "legacy" ? ["chromium"] : ["chromium", "firefox", "webkit"];
const runs = browsers.map((browser) => {
  const output = join(directory, `${backend}-${browser}-vitest.json`);
  if (existsSync(output)) rmSync(output);
  const run = spawnSync(process.execPath, [
  join(root, "node_modules/vitest/vitest.mjs"), "run",
  "--testNamePattern", `^(${[...selected, ...milestone].map((t) => escape(t.fullName)).join("|")})$`,
  "--reporter=default", "--reporter=json", "--reporter=junit",
  `--outputFile.json=${output}`, `--outputFile.junit=${join(directory, `${backend}-${browser}-junit.xml`)}`,
], { cwd: root, env: { ...process.env, CONTRACT_BACKEND: backend, CONTRACT_BROWSER: browser }, stdio: "inherit", timeout: 180_000 });
if (run.error) throw run.error;
const result = JSON.parse(readFileSync(output, "utf8")) as {
  testResults: { assertionResults: { fullName: string; status: string }[] }[];
};
const assertions = result.testResults.flatMap((test) => test.assertionResults);
const outcomes: Observation[] = [...selected, ...milestone].map((test) => {
  const matching = assertions.filter((a) => a.fullName === test.fullName);
  if (matching.length !== 1 || !["passed", "failed"].includes(matching[0].status))
    throw new Error(`Missing, duplicate, or skipped oracle test: ${test.fullName}`);
  return { id: test.id, status: matching[0].status === "passed" ? "passed" : "failed" };
});
if (assertions.filter((a) => a.status === "passed" || a.status === "failed").length !== selected.length + milestone.length)
  throw new Error("Unexpected tests executed outside the declared browser selection");
return { browser, exit: run.status, signal: run.signal, outcomes };
});
const observations: Observation[] = selected.map((test) => ({
  id: test.id,
  status: runs.every((run) => run.outcomes.find((o) => o.id === test.id)?.status === "passed") ? "passed" : "failed",
}));
assertFreshEvidence(fingerprint, {
  inventorySha256: hash(JSON.stringify(buildInventory())),
  lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
  artifactsSha256: hash(JSON.stringify(backend === "legacy" ? legacyArtifacts() : stateArtifacts())),
  harnessSha256: harnessFingerprint(),
});
writeFileSync(evidence, JSON.stringify({
  backend, browsers, runs,
  upstreamCommit: pin.commit,
  ...fingerprint,
  artifacts,
  observations,
}, null, 2) + "\n");
if (runs.some((run) => run.exit !== 0 || run.outcomes.some((o) => o.status !== "passed")))
  throw new Error(`${backend} browser proof failed; failing observations recorded`);
console.log(`Recorded ${observations.length} unchanged upstream passes and ${milestone.length} M1 cases on ${browsers.join(", ")}.`);
