import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { assertFreshEvidence, buildInventory, extractTests, harnessFingerprint, hash, legacyArtifacts, loadInventory, pin, root, stateArtifacts, type Observation } from "./contract.ts";
import { assertRuntimeRuns, runtimeObservations } from "./runtime-record.ts";

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
  ? ["m1", "m2", "m3", "m3-worker", "m3-settings"].flatMap((name) => {
    const file = `browser/${name}.spec.ts`;
    return extractTests(readFileSync(join(root, file), "utf8"), file);
  }) : [];
if (backend === "state-machine" && (milestone.length === 0 || milestone.some((t) => t.parameterized || t.sourceMode !== "normal")))
  throw new Error("Browser milestones require explicit, non-skipped tests");
const artifacts = backend === "legacy" ? legacyArtifacts() : stateArtifacts();
const fingerprint = {
  inventorySha256: hash(JSON.stringify(inventory)),
  lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
  artifactsSha256: hash(JSON.stringify(artifacts)),
  harnessSha256: harnessFingerprint(),
};
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const browsers = backend === "legacy" ? ["chromium"] : ["chromium", "firefox", "webkit"];
function execute(browser: string, runtime: "inline" | "worker") {
  const selection = runtime === "worker" ? selected : [...selected, ...milestone];
  const suffix = runtime === "worker" ? "-worker" : "";
  const output = join(directory, `${backend}${suffix}-${browser}-vitest.json`);
  if (existsSync(output)) rmSync(output);
  const run = spawnSync(process.execPath, [
  join(root, "node_modules/vitest/vitest.mjs"), "run",
  "--testNamePattern", `^(${selection.map((t) => escape(t.fullName)).join("|")})$`,
  "--reporter=default", "--reporter=json", "--reporter=junit",
 `--outputFile.json=${output}`, `--outputFile.junit=${join(directory, `${backend}${suffix}-${browser}-junit.xml`)}`,
], { cwd: root, env: { ...process.env, CONTRACT_BACKEND: backend, CONTRACT_BROWSER: browser,
  CONTRACT_RUNTIME: runtime }, stdio: "inherit", timeout: 180_000 });
if (run.error) throw run.error;
const result = JSON.parse(readFileSync(output, "utf8")) as {
  testResults: { assertionResults: { fullName: string; status: string }[] }[];
};
const assertions = result.testResults.flatMap((test) => test.assertionResults);
const outcomes: Observation[] = selection.map((test) => {
  const matching = assertions.filter((a) => a.fullName === test.fullName);
  if (matching.length !== 1 || !["passed", "failed"].includes(matching[0].status))
    throw new Error(`Missing, duplicate, or skipped oracle test: ${test.fullName}`);
  return { id: test.id, status: matching[0].status === "passed" ? "passed" : "failed" };
});
if (assertions.filter((a) => a.status === "passed" || a.status === "failed").length !== selection.length)
  throw new Error("Unexpected tests executed outside the declared browser selection");
return { browser, runtime, exit: run.status, signal: run.signal, outcomes };
}
const runs = browsers.map((browser) => execute(browser, "inline"));
const runtimeRuns = backend === "state-machine" ? [
  ...runs.map((run) => ({ ...run, outcomes: run.outcomes.filter((o) => selected.some((test) => test.id === o.id)) })),
  ...browsers.map((browser) => execute(browser, "worker")),
] : undefined;
if (runtimeRuns) assertRuntimeRuns(runtimeRuns, selected.map((test) => test.id));
const observations: Observation[] = runtimeRuns ? runtimeObservations(runtimeRuns, selected.map((test) => test.id)) : selected.map((test) => ({
  id: test.id,
  status: (runtimeRuns ?? runs).every((run) => run.exit === 0 &&
    run.outcomes.find((o) => o.id === test.id)?.status === "passed") ? "passed" : "failed",
}));
assertFreshEvidence(fingerprint, {
  inventorySha256: hash(JSON.stringify(buildInventory())),
  lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
  artifactsSha256: hash(JSON.stringify(backend === "legacy" ? legacyArtifacts() : stateArtifacts())),
  harnessSha256: harnessFingerprint(),
});
writeFileSync(evidence, JSON.stringify({
  backend, browsers, runs, runtimeRuns,
  upstreamCommit: pin.commit,
  ...fingerprint,
  artifacts,
  observations,
}, null, 2) + "\n");
if ([...runs, ...(runtimeRuns ?? [])].some((run) => run.exit !== 0 || run.outcomes.some((o) => o.status !== "passed")))
  throw new Error(`${backend} browser proof failed; failing observations recorded`);
console.log(`Recorded ${observations.length} unchanged upstream passes${runtimeRuns ? " on inline and Worker" : ""} and ${milestone.length} M1/M2/M3 cases on ${browsers.join(", ")}.`);
