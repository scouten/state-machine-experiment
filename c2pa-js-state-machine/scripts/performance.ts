import { mkdirSync, readFileSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { buildInventory, hash, loadInventory, pin, root, legacyArtifacts, stateArtifacts, harnessFingerprint } from "./contract.ts";
import { assertPerformanceRecord } from "./performance-record.ts";

if (hash(JSON.stringify(buildInventory())) !== hash(JSON.stringify(loadInventory())))
  throw new Error("Pinned source differs from inventory");
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")) as {
  packages: Record<string, { version?: string; integrity?: string }>;
};
const sdk = lock.packages[`node_modules/${pin.legacyPackage}`];
if (sdk?.version !== pin.legacyVersion || sdk.integrity !== pin.legacyIntegrity)
  throw new Error("Legacy SDK version/integrity differs from upstream.json");
const browsers = process.argv.includes("--all-browsers") ? ["chromium", "firefox", "webkit"] : ["chromium"];
const output = join(root, "results", "performance.json");
mkdirSync(join(root, "results"), { recursive: true });
if (existsSync(output)) rmSync(output);
const fingerprint = () => ({
  inventory: hash(JSON.stringify(buildInventory())),
  lock: hash(readFileSync(join(root, "package-lock.json"))),
  legacy: legacyArtifacts(), state: stateArtifacts(), harness: harnessFingerprint(),
});
const before = fingerprint();
const reports = [];
for (const browser of browsers) {
  const run = spawnSync(process.execPath, [join(root, "node_modules/vitest/vitest.mjs"), "run",
    "--reporter=default"], {
    cwd: root, env: { ...process.env, CONTRACT_BACKEND: "state-machine", CONTRACT_PERFORMANCE: "1", CONTRACT_BROWSER: browser },
    encoding: "utf8", timeout: 300_000, maxBuffer: 8 * 1024 * 1024,
  });
  process.stdout.write((run.stdout ?? "").split("\n").filter((line) => !line.includes("BOUNDARY_PERFORMANCE ")).join("\n"));
  process.stderr.write(run.stderr ?? "");
  if (run.error) throw run.error;
  if (run.status !== 0) throw new Error(`${browser} performance proof failed`);
  const records = [...run.stdout.matchAll(/BOUNDARY_PERFORMANCE (\{[^\n]+\})/g)]
    .map((match) => {
      const record: unknown = JSON.parse(match[1]);
      assertPerformanceRecord(record);
      return record;
    });
  if (records.length !== 2 || !["unsigned", "trusted-signed"].every(
    (name) => records.filter((record) => record.case === name).length === 1))
    throw new Error(`Missing or duplicate ${browser} measurements`);
  const summaries = [];
  for (const record of records) {
    for (const run of record.runs) {
      for (const [backend, samples] of Object.entries(run.results)) {
        const sorted = samples.map((sample) => sample.durationMs).sort((a, b) => a - b);
        const medianMs = (sorted[4] + sorted[5]) / 2;
        const p95Ms = sorted[9];
        summaries.push({ case: record.case, mode: run.mode, backend, medianMs, p95Ms,
          calls: samples[0].calls, bytesReturned: samples[0].bytesReturned,
          messages: samples[0].messages,
          ...(samples[0].readAhead ? { readAhead: samples[0].readAhead } : {}),
          ...(backend === "state-machine-worker" || backend === "state-machine-read-ahead" ? {
            medianWorkerExecutionMs: samples.map((s) => {
              if (s.workerExecutionMs === undefined) throw new Error("Missing Worker execution duration");
              return s.workerExecutionMs;
            }).sort((a, b) => a - b)
              .slice(4, 6).reduce((a, b) => a + b, 0) / 2,
          } : {}) });
        console.log(`${browser} ${record.case} ${run.mode} ${backend}: median=${medianMs.toFixed(2)}ms p95=${p95Ms.toFixed(2)}ms calls=${samples[0].calls} bytes=${samples[0].bytesReturned}`);
      }
    }
  }
  reports.push({ browser, summaries, records });
}
if (JSON.stringify(before) !== JSON.stringify(fingerprint()))
  throw new Error("Performance inputs changed during measurement");
writeFileSync(output, JSON.stringify({
  schema: 3, measuredAt: new Date().toISOString(), upstreamCommit: pin.commit,
  warmupReads: 2, measuredReads: 10, fingerprints: before, reports,
  limitations: [
    "Four paths: legacy Worker, new inline, new Worker and test-only 4 KiB read-ahead Worker. Worker location does not match Wasm code, loader or I/O implementation; not isolated FFI cost.",
    "Legacy synchronous reads use a test-only busy wait for injected delay; state-machine reads await a timer. Synthetic timings are not native throughput.",
    "Host service time includes sync read duration on legacy, not exclusively await time.",
    "State Wasm initialization is shared per realm; reported setup can be warm. First operation is separate from warmed samples.",
    "Read telemetry excludes length/clock lookups and internal session steps. Message counts cover only fromBlob, not validation queries or free.",
    "Legacy adds one telemetry packet per read; new Worker adds one aggregate packet per operation; inline telemetry is local. Instrumentation overhead is included.",
    "New Worker execution span includes context decoding, read/validation and instrumentation, but excludes caller queue/clone costs and telemetry delivery. Subtracting it from caller duration does not isolate FFI.",
    "Worker setup includes fresh Worker startup with potentially warm browser Wasm/network caches; inline Wasm is shared. These are not cold-start distributions.",
    "Ten warmed samples per series: exploratory median/p95, not a stable production regression budget.",
    "Signed fixture is generated once per browser run; all four paths receive identical bytes, with the asset hash recorded.",
    "Read-ahead uses one operation-local 4 KiB window only for reads up to 64 bytes; larger reads bypass it. It trades extra physical bytes for fewer Blob reads without changing logical session requests.",
    "Read-ahead cache occupancy is instrumented, not whole-process peak memory; current async host serializes reads. No production optimization is enabled.",
    "Small fixtures only. No large-asset memory, event-loop responsiveness or production performance budget is proven.",
  ],
}, null, 2) + "\n");
console.log(`Saved verified measurements to ${output}`);
