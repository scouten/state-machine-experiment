import type { ReadAheadStats } from "./read-ahead.ts";
export const backends = ["legacy", "state-machine", "state-machine-worker", "state-machine-read-ahead"] as const;
export type Backend = typeof backends[number];
export interface ReadMetric { bytes: number; milliseconds: number; transport: "sync" | "async" }
export interface WorkerCounts { toWorker: number; fromWorker: number; telemetry: number }
export interface Sample {
  durationMs: number;
  hostServiceMs: number;
  calls: number;
  bytesRequested: number;
  bytesReturned: number;
  readSizes: number[];
  transports: Record<"sync" | "async", number>;
  messages: WorkerCounts;
  workerExecutionMs?: number;
  readAhead?: ReadAheadStats;
}
export interface PerformanceRecord {
  schema: 3;
  case: "unsigned" | "trusted-signed";
  assetBytes: number;
  assetSha256: string;
  userAgent: string;
  stateInitializationMs: number;
  runs: {
    mode: "natural" | "delay-0" | "delay-2";
    delayMs: number;
    legacyInitializationMs: number;
    workerInitializationMs: number;
    readAheadInitializationMs: number;
    firstOperationMs: Partial<Record<Backend, number>>;
    results: Record<Backend, Sample[]>;
  }[];
}
