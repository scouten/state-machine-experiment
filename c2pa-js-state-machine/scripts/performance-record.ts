import { backends, type PerformanceRecord } from "../browser/performance-types.ts";
import { smallReadBytes, windowBytes, type ReadAheadStats } from "../browser/read-ahead.ts";

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function timing(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}
function count(value: unknown): value is number { return timing(value) && Number.isSafeInteger(value) }
export function assertReadAheadStats(value: unknown): asserts value is ReadAheadStats {
  if (!object(value) || value.windowBytes !== windowBytes ||
      !Array.isArray(value.logicalReadSizes) || !value.logicalReadSizes.every(count) ||
      !count(value.hits) || !count(value.fills) || !count(value.bypasses) ||
      value.hits + value.fills + value.bypasses !== value.logicalReadSizes.length ||
      !count(value.maxResidentBytes) || value.maxResidentBytes > windowBytes)
    throw new Error("Invalid read-ahead measurements");
}
export function assertPerformanceRecord(value: unknown): asserts value is PerformanceRecord {
  if (!object(value) || value.schema !== 3 ||
      !["unsigned", "trusted-signed"].includes(String(value.case)) ||
      !count(value.assetBytes) || value.assetBytes === 0 ||
      typeof value.assetSha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.assetSha256) ||
      typeof value.userAgent !== "string" || value.userAgent.length === 0 ||
      !timing(value.stateInitializationMs) || !Array.isArray(value.runs) || value.runs.length !== 3)
    throw new Error("Invalid performance record");
  const modes = ["natural", "delay-0", "delay-2"];
  for (const mode of modes) {
    if (value.runs.filter((run: unknown) => object(run) && run.mode === mode).length !== 1)
      throw new Error("Missing or duplicate performance mode");
  }
  for (const run of value.runs) {
    if (!object(run) || run.delayMs !== (run.mode === "delay-2" ? 2 : 0) ||
        !timing(run.legacyInitializationMs) || !timing(run.workerInitializationMs) ||
        !timing(run.readAheadInitializationMs) ||
        !object(run.firstOperationMs) || !object(run.results) ||
        Object.keys(run.results).length !== backends.length ||
        Object.keys(run.firstOperationMs).length !== backends.length)
      throw new Error("Invalid performance run");
    for (const backend of backends) {
      const samples = run.results[backend];
      if (!timing(run.firstOperationMs[backend]) || !Array.isArray(samples) || samples.length !== 10)
        throw new Error("Missing backend or invalid sample count");
      const expectedCalls = backend === "legacy" ? 1 : value.case === "unsigned" ? 10 : 15;
      const expectedBytes = backend === "legacy" ? value.assetBytes : value.case === "unsigned" ? 38 : value.assetBytes + 38;
      for (const sample of samples) {
        const buffered = backend === "state-machine-read-ahead";
        if (!object(sample)) throw new Error("Invalid performance sample");
        let physicalCalls = expectedCalls;
        let physicalBytes = expectedBytes;
        if (buffered) {
          assertReadAheadStats(sample.readAhead);
          physicalCalls = sample.readAhead.fills + sample.readAhead.bypasses;
          const bypassSizes = sample.readAhead.logicalReadSizes.filter((size) => size > smallReadBytes);
          const expectedPhysicalSizes = [windowBytes, ...bypassSizes];
          if (sample.readAhead.logicalReadSizes.length !== expectedCalls ||
              sample.readAhead.logicalReadSizes.reduce((a, b) => a + b, 0) !== expectedBytes ||
              physicalCalls !== (value.case === "unsigned" ? 1 : 4) ||
              sample.readAhead.fills !== 1 || sample.readAhead.bypasses !== bypassSizes.length ||
              sample.readAhead.maxResidentBytes !== windowBytes ||
              JSON.stringify(sample.readSizes) !== JSON.stringify(expectedPhysicalSizes) ||
              sample.bytesReturned !== expectedPhysicalSizes.reduce((a, b) => a + b, 0))
            throw new Error("Read-ahead changed logical requests or did not reduce physical reads");
          physicalBytes = expectedPhysicalSizes.reduce((a, b) => a + b, 0);
        } else if (sample.readAhead !== undefined) throw new Error("Unexpected read-ahead measurements");
        if (!object(sample) || !timing(sample.durationMs) || !timing(sample.hostServiceMs) ||
            sample.calls !== physicalCalls || sample.bytesRequested !== physicalBytes || sample.bytesReturned !== physicalBytes ||
            !Array.isArray(sample.readSizes) || sample.readSizes.length !== physicalCalls ||
            !sample.readSizes.every(count) || sample.readSizes.reduce((a: number, b: number) => a + b, 0) !== physicalBytes ||
            !object(sample.transports) ||
            sample.transports.sync !== (backend === "legacy" ? 1 : 0) ||
            sample.transports.async !== (backend === "legacy" ? 0 : physicalCalls) ||
            !object(sample.messages) || !count(sample.messages.toWorker) ||
            !count(sample.messages.fromWorker) || !count(sample.messages.telemetry))
          throw new Error("Invalid performance sample or changed read baseline");
        if (backend === "state-machine-worker" || buffered) {
          if (!timing(sample.workerExecutionMs) || sample.messages.toWorker !== 1 ||
              sample.messages.fromWorker !== 1 || sample.messages.telemetry !== 1)
            throw new Error("Invalid Worker execution measurements");
        } else if (backend === "state-machine") {
          if (sample.workerExecutionMs !== undefined || Object.values(sample.messages).some((v) => v !== 0))
            throw new Error("Inline measurement contains Worker traffic");
        } else if (sample.workerExecutionMs !== undefined || sample.messages.toWorker === 0 ||
            sample.messages.fromWorker === 0 || sample.messages.telemetry !== expectedCalls)
          throw new Error("Missing legacy Worker measurements");
        if (JSON.stringify(sample.readSizes) !== JSON.stringify(samples[0].readSizes))
          throw new Error("Read sizes changed across samples");
      }
    }
    const inline = run.results["state-machine"];
    const worker = run.results["state-machine-worker"];
    const buffered = run.results["state-machine-read-ahead"];
    if (!Array.isArray(inline) || !Array.isArray(worker) ||
        JSON.stringify(inline[0].readSizes) !== JSON.stringify(worker[0].readSizes))
      throw new Error("Worker and inline read ranges differ");
    if (!Array.isArray(buffered) || buffered.some((sample) =>
      JSON.stringify(sample.readAhead.logicalReadSizes) !== JSON.stringify(worker[0].readSizes)))
      throw new Error("Read-ahead and baseline logical ranges differ");
  }
  for (const backend of backends) {
    for (const run of value.runs.slice(1)) {
      if (JSON.stringify(run.results[backend][0].readSizes) !==
          JSON.stringify(value.runs[0].results[backend][0].readSizes))
        throw new Error("Read sizes changed across delay modes");
    }
  }
}
