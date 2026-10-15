import { test } from "node:test";
import assert from "node:assert/strict";
import { assertPerformanceRecord } from "../scripts/performance-record.ts";
import { backends, type Backend, type PerformanceRecord, type Sample } from "../browser/performance-types.ts";

function record(): PerformanceRecord {
  const result = (backend: Backend): Sample => {
    const legacy = backend === "legacy";
    const buffered = backend === "state-machine-read-ahead";
    return {
      durationMs: 1, hostServiceMs: 0.5, calls: legacy || buffered ? 1 : 10,
      bytesRequested: legacy ? 5000 : buffered ? 4096 : 38, bytesReturned: legacy ? 5000 : buffered ? 4096 : 38,
      readSizes: legacy ? [5000] : buffered ? [4096] : [2, 4, 4, 4, 4, 4, 4, 4, 4, 4],
      transports: { sync: legacy ? 1 : 0, async: legacy ? 0 : buffered ? 1 : 10 },
      messages: { toWorker: backend === "state-machine" ? 0 : 1,
        fromWorker: backend === "state-machine" ? 0 : 1,
        telemetry: backend === "state-machine" ? 0 : 1 },
      ...(backend === "state-machine-worker" || buffered ? { workerExecutionMs: 0.75 } : {}),
      ...(buffered ? { readAhead: { windowBytes: 4096, logicalReadSizes: [2, 4, 4, 4, 4, 4, 4, 4, 4, 4],
        hits: 9, fills: 1, bypasses: 0, maxResidentBytes: 4096 } } : {}),
    };
  };
  return {
    schema: 3, case: "unsigned", assetBytes: 5000, assetSha256: "a".repeat(64),
    userAgent: "test", stateInitializationMs: 1,
    runs: (["natural", "delay-0", "delay-2"] as const).map((mode) => ({
      mode, delayMs: mode === "delay-2" ? 2 : 0,
      legacyInitializationMs: 1, workerInitializationMs: 1, readAheadInitializationMs: 1,
      firstOperationMs: { legacy: 1, "state-machine": 1, "state-machine-worker": 1, "state-machine-read-ahead": 1 },
      results: {
        legacy: Array.from({ length: 10 }, () => result("legacy")),
        "state-machine": Array.from({ length: 10 }, () => result("state-machine")),
        "state-machine-worker": Array.from({ length: 10 }, () => result("state-machine-worker")),
        "state-machine-read-ahead": Array.from({ length: 10 }, () => result("state-machine-read-ahead")),
      },
    })),
  };
}
test("matched Worker performance records require every path mode sample and measured field", () => {
  assert.doesNotThrow(() => assertPerformanceRecord(record()));
  const mutations: ((value: PerformanceRecord) => void)[] = [
    (value) => { value.runs.pop() },
    (value) => { value.runs[1].mode = "natural" },
    (value) => { value.runs[2].delayMs = 0 },
    (value) => { Reflect.deleteProperty(value.runs[0].results, "state-machine-worker") },
    (value) => { value.runs[0].results["state-machine-worker"].pop() },
    (value) => { delete value.runs[0].results["state-machine-worker"][0].workerExecutionMs },
    (value) => { value.runs[0].results["state-machine-worker"][0].messages.telemetry = 0 },
    (value) => { value.runs[0].results["state-machine-worker"][0].workerExecutionMs = NaN },
    (value) => { value.runs[0].results["state-machine"][0].messages.toWorker = 1 },
    (value) => { value.runs[0].results.legacy[0].bytesReturned = 99 },
    (value) => { value.runs[0].results["state-machine-worker"][0].readSizes.reverse() },
    (value) => { delete value.runs[0].results["state-machine-read-ahead"][0].readAhead },
    (value) => { value.runs[0].results["state-machine-read-ahead"][0].readAhead!.maxResidentBytes = 4097 },
    (value) => { value.runs[0].results["state-machine-read-ahead"][0].readAhead!.logicalReadSizes.reverse() },
    (value) => { value.runs[0].results["state-machine-read-ahead"][0].bytesReturned = 4095 },
    (value) => { value.runs[0].results["state-machine-read-ahead"][0].readAhead!.hits = 8 },
  ];
  for (const mutation of mutations) {
    const changed = record();
    mutation(changed);
    assert.throws(() => assertPerformanceRecord(changed));
  }
  for (const backend of backends) {
    for (const duration of [NaN, Infinity, -1]) {
      const changed = record();
      changed.runs[0].results[backend][0].durationMs = duration;
      assert.throws(() => assertPerformanceRecord(changed));
    }
  }
});
test("signed read-ahead evidence preserves hash chunks and accounts for every extra physical byte", () => {
  const value = record();
  value.case = "trusted-signed";
  value.assetBytes = 88487;
  const logical = [2, 4, 4, 1849, 4, 4, 4, 4, 4, 4, 4, 4, 20, 65536, 21078];
  for (const run of value.runs) for (const backend of backends) {
    for (const sample of run.results[backend]) {
      const physical = backend === "legacy" ? [88487] :
        backend === "state-machine-read-ahead" ? [4096, 1849, 65536, 21078] : logical;
      sample.readSizes = [...physical];
      sample.calls = physical.length;
      sample.bytesRequested = sample.bytesReturned = physical.reduce((a, b) => a + b, 0);
      sample.transports = { sync: backend === "legacy" ? 1 : 0, async: backend === "legacy" ? 0 : physical.length };
      if (sample.readAhead) {
        sample.readAhead = { windowBytes: 4096, logicalReadSizes: [...logical],
          hits: 11, fills: 1, bypasses: 3, maxResidentBytes: 4096 };
      }
    }
  }
  assert.doesNotThrow(() => assertPerformanceRecord(value));
  value.runs[0].results["state-machine-read-ahead"][0].readSizes[2] = 65535;
  assert.throws(() => assertPerformanceRecord(value));
});
