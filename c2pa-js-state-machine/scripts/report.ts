import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { assertFreshEvidence, buildInventory, extractTests, harnessFingerprint, hash, legacyArtifacts, loadInventory, parityReport, pin, root, stateArtifacts, type Observation } from "./contract.ts";
import { assertPackageRecord } from "./package-record.ts";
import { assertRuntimeRuns, runtimeObservations, type RuntimeRun } from "./runtime-record.ts";

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
const stateObservations = observations("state-machine");
const report = parityReport(inventory, observations("legacy"), stateObservations);
const stateEvidence = join(root, "results/state-machine-observations.json");
const m1 = existsSync(stateEvidence) ? JSON.parse(readFileSync(stateEvidence, "utf8")) as {
  backend: string; browsers: string[]; runs: { browser: string; exit: number; outcomes: Observation[] }[];
  runtimeRuns?: RuntimeRun[];
} : undefined;
if (m1 && (m1.backend !== "state-machine" ||
    JSON.stringify(m1.browsers) !== JSON.stringify(["chromium", "firefox", "webkit"]) ||
    JSON.stringify(m1.runs.map((run) => run.browser)) !== JSON.stringify(m1.browsers)))
  throw new Error("M1 evidence must cover all three required browsers");
if (m1) {
  assertRuntimeRuns(m1.runtimeRuns, inventory.tests.filter((test) =>
    test.file === "packages/c2pa-web/src/lib/reader.spec.ts" && pin.oracleTests.includes(test.title)).map((test) => test.id));
  if (JSON.stringify(runtimeObservations(m1.runtimeRuns, stateObservations.map((o) => o.id))) !== JSON.stringify(stateObservations))
    throw new Error("Upstream observations disagree with inline/Worker runtime evidence");
  for (const [index, run] of m1.runs.entries()) {
    const matrix = m1.runtimeRuns[index];
    const upstream = run.outcomes.filter((outcome) => stateObservations.some((o) => o.id === outcome.id));
    if (matrix.exit !== run.exit || JSON.stringify(matrix.outcomes) !== JSON.stringify(upstream))
      throw new Error("Inline upstream matrix disagrees with milestone evidence");
  }
  const required = [
    ...inventory.tests.filter((test) => test.file === "packages/c2pa-web/src/lib/reader.spec.ts" && pin.oracleTests.includes(test.title)),
    ...["m1", "m2", "m3", "m3-worker", "m3-settings", "m3-resources"].flatMap((name) => {
      const file = `browser/${name}.spec.ts`;
      return extractTests(readFileSync(join(root, file), "utf8"), file);
    }),
  ].map((test) => test.id);
  for (const run of m1.runs) {
    const ids = run.outcomes.map((outcome) => outcome.id);
    if (ids.length !== required.length || new Set(ids).size !== required.length ||
        !required.every((id) => ids.includes(id)))
      throw new Error(`Missing, duplicate, or unexpected milestone evidence for ${run.browser}`);
  }
}
const m1Ids = new Set([
  ...inventory.tests.filter((test) => test.file === "packages/c2pa-web/src/lib/reader.spec.ts" && pin.oracleTests.includes(test.title)),
  ...extractTests(readFileSync(join(root, "browser/m1.spec.ts"), "utf8"), "browser/m1.spec.ts"),
].map((test) => test.id));
const m2Tests = extractTests(readFileSync(join(root, "browser/m2.spec.ts"), "utf8"), "browser/m2.spec.ts");
const m3Tests = ["m3", "m3-worker", "m3-settings", "m3-resources"].flatMap((name) => {
  const file = `browser/${name}.spec.ts`;
  return extractTests(readFileSync(join(root, file), "utf8"), file);
});
const milestone = m1 ? {
  browsers: m1.browsers,
  passed: m1.runs.every((run) => run.exit === 0 && run.outcomes
    .filter((outcome) => m1Ids.has(outcome.id)).every((outcome) => outcome.status === "passed")),
  executions: m1.runs.reduce((count, run) => count + run.outcomes
    .filter((outcome) => m1Ids.has(outcome.id)).length, 0),
} : { passed: false, blocker: "M1 browser proof has not run" };
const m2 = m1 ? {
  browsers: m1.browsers,
  passed: m1.runs.every((run) => run.exit === 0 && run.outcomes
    .filter((outcome) => m2Tests.some((test) => test.id === outcome.id))
    .every((outcome) => outcome.status === "passed")),
  executions: m1.runs.reduce((count, run) => count + run.outcomes
    .filter((outcome) => m2Tests.some((test) => test.id === outcome.id)).length, 0),
  scope: "CBOR assertion payloads, validation-result buckets, CAWG trust anchors, unsupported unchecked remote-manifest setting rejection",
} : { passed: false, blocker: "M2 browser proof has not run" };
const m3 = m1 ? {
  browsers: m1.browsers,
  passed: m1.runs.every((run) => run.exit === 0 && run.outcomes
    .filter((outcome) => m3Tests.some((test) => test.id === outcome.id))
    .every((outcome) => outcome.status === "passed")),
  executions: m1.runs.reduce((count, run) => count + run.outcomes
    .filter((outcome) => m3Tests.some((test) => test.id === outcome.id)).length, 0),
  scope: "Detached input/output and full-asset binding; JPEG XMP remote discovery and bounded host fetch with CORS/retry; signed browser OCSP with default-off, revocation, inaccessible, limits/deadlines/abort; TIFF/BigTIFF both byte orders, tampering, detached reads and legacy classic-TIFF validation (native tests pin separate exclusions); module Worker URL/precompiled loading, read/sign callbacks, network cancellation and resource cleanup; genuine local RFC3161 Worker timestamps with inline/legacy read-back, concurrent routing, URL precedence, detached parity, wrong-imprint reporting and explicit failure/retry; supported reader-factory loader defaults, legacy deep merging and static Context isolation, runtime snapshots, builder-default rejection and inherited OCSP host gating; embedded binary assertion extraction with legacy claim-thumbnail metadata/bytes, independent copies, unknown-ID recovery, URI scoping and free/dispose checks; exact legacy active-manifest and single-manifest trusted/untrusted store equality, verified signer metadata unchanged by independent claim/identity trust anchors, failure-only summaries preserving tamper failures and unrelated successes, and scoped named trust-list provenance; parsed legacy JSON equality for trusted/untrusted stores, signed numeric-array/base64 display edge cases, unchanged object views and repeated-call/lifecycle checks on inline and Worker; explicit claim-trust opt-out and independent CAWG anchor switches with complete object/JSON legacy comparisons, failure-preserving Valid cap and factory false-default re-enabling; v1/v2/v3 ingredient metadata and unknown-provenance deltas with complete object/JSON legacy comparison, explicit linked/history rejection, lifecycle recovery and preserved live tamper failures; real c2pa-rs-signed embedded generator icons and positional ingredient thumbnails/data with complete trusted legacy reports, exact independent bytes, thumbnail/data coexistence, isolated live tamper failures, explicit databox rejection and recovery; external/cross-owner/malformed/missing/ambiguous reference rejection without implicit fetching",
} : { passed: false, blocker: "M3 browser proof has not run" };
const packagePath = join(root, "results/package.json");
let packaging: { passed: boolean; executions?: number; scope?: string; blocker?: string } =
  { passed: false, blocker: "Private packed-consumer proof has not run" };
if (existsSync(packagePath)) {
  const evidence: unknown = JSON.parse(readFileSync(packagePath, "utf8"));
  assertPackageRecord(evidence, {
    inventorySha256: hash(JSON.stringify(inventory)),
    lockSha256: hash(readFileSync(join(root, "package-lock.json"))),
    harnessSha256: harnessFingerprint(), artifactsSha256: hash(JSON.stringify(stateArtifacts())),
  });
  packaging = { passed: true, executions: evidence.reports.reduce((count, run) => count + run.paths.length, 0),
    scope: "Private npm tarball installed in an isolated consumer; emitted ESM/types/Wasm exports; Vite production build; inline/module Worker URL and precompiled Wasm loading, sign/read cross-validation, detached output, exact claim-thumbnail/generator-icon/positional ingredient-thumbnail/data extraction and copy ownership with thumbnail/data coexistence, claim signer metadata, failure summaries and distinct legacy JSON base64/object-array views, disabled claim-trust overrides retaining signature validation, ingredient metadata/reviews, malformed rejection and cleanup, concurrent Context isolation and cached-policy reuse in three browsers" };
}
const readerRuntimes = m1?.runtimeRuns ? {
  passed: m1.runtimeRuns.every((run) => run.exit === 0 && run.outcomes.every((o) => o.status === "passed")),
  executions: m1.runtimeRuns.reduce((count, run) => count + run.outcomes.length, 0),
  runtimes: ["inline", "worker"], browsers: ["chromium", "firefox", "webkit"],
  scope: `${pin.oracleTests.length} unchanged pinned upstream reader cases on both state-machine runtime paths, including creation/omitted-format detection, explicit/independent/reused Contexts, deprecated factory creation/merging, embedded thumbnail extraction, active-manifest and trusted/untrusted/disabled-trust store equality; runtime executions do not increase the unique upstream declaration count`,
} : { passed: false, blocker: "Upstream inline/Worker matrix has not run" };
const completeReport = { ...report, m1: milestone, m2, m3, packaging, readerRuntimes };
mkdirSync(join(root, "results"), { recursive: true });
writeFileSync(join(root, "results/parity.json"), JSON.stringify(completeReport, null, 2) + "\n");
console.log(JSON.stringify({
  upstreamCommit: report.upstreamCommit,
  denominator: report.denominator,
  legacy: report.legacy,
  stateMachine: report.stateMachine,
  fullParity: report.fullParity,
  m1: milestone,
  m2,
  m3,
  packaging,
  readerRuntimes,
}, null, 2));
if (process.argv.includes("--require-parity") && !report.fullParity) process.exitCode = 1;
