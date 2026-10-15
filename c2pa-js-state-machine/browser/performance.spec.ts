import { afterEach, expect, test, vi } from "vitest";
import { createC2pa, Builder, Context, Reader, type Signer } from "c2pa-js-state-machine/inline";
import { createC2pa as createLegacy, Context as LegacyContext, Reader as LegacyReader } from "@contentauth/c2pa-web";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import legacyWasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import unsignedSrc from "test/assets/C_with_CAWG_data_thumbnail.jpg?url";
import fixtures from "../.cache/generated/fixtures.json" with { type: "json" };
import { createC2pa as createWorker, Reader as WorkerReader } from "c2pa-js-state-machine/worker";
import workerSrc from "./performance-worker.ts?worker&url";
import { backends, type Backend, type PerformanceRecord, type ReadMetric, type Sample, type WorkerCounts } from "./performance-types.ts";
import { type ReadAheadStats } from "./read-ahead.ts";
import { assertReadAheadStats } from "../scripts/performance-record.ts";

const frozen = Date.parse("2026-09-01T00:00:00Z");
const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
const settings = { trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } };
const samples = 10;
const counts = (): WorkerCounts => ({ toWorker: 0, fromWorker: 0, telemetry: 0 });
function metric(value: unknown): ReadMetric {
  if (typeof value !== "object" || value === null ||
      !("bytes" in value) || !Number.isSafeInteger(value.bytes) || typeof value.bytes !== "number" || value.bytes < 0 ||
      !("milliseconds" in value) || typeof value.milliseconds !== "number" || !Number.isFinite(value.milliseconds) || value.milliseconds < 0 ||
      !("transport" in value) || (value.transport !== "sync" && value.transport !== "async"))
    throw new Error("Invalid host measurement");
  return { bytes: value.bytes, milliseconds: value.milliseconds, transport: value.transport };
}

function measuredBlob(blob: Blob, reads: ReadMetric[], delay: number): Blob {
  class Slice extends Blob {
    override async arrayBuffer(): Promise<ArrayBuffer> {
      const started = performance.now();
      if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
      const result = await super.arrayBuffer();
      reads.push({ bytes: result.byteLength, milliseconds: performance.now() - started, transport: "async" });
      expect(result.byteLength).toBe(this.size);
      return result;
    }
  }
  class Source extends Blob {
    override slice(start?: number, end?: number, type?: string): Blob {
      return new Slice([super.slice(start, end, type)]);
    }
  }
  return new Source([blob], { type: blob.type });
}

function instrumentLegacy(reads: ReadMetric[], delay: number, messages: WorkerCounts) {
  const NativeWorker = Worker;
  vi.stubGlobal("Worker", class extends NativeWorker {
    constructor(url: string | URL, options?: WorkerOptions) {
      super(url, options);
      this.addEventListener("message", (event: MessageEvent<unknown>) => {
        const value = event.data;
        if (typeof value === "object" && value !== null && "boundaryRead" in value) {
          messages.telemetry++;
          reads.push(metric(value.boundaryRead));
        } else messages.fromWorker++;
      });
    }
    override postMessage(message: unknown, options?: Transferable[] | StructuredSerializeOptions): void {
      messages.toWorker++;
      if (Array.isArray(options)) super.postMessage(message, options);
      else super.postMessage(message, options);
    }
  });
  const createURL = URL.createObjectURL.bind(URL);
  let injected = false;
  vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
    if (!(blob instanceof Blob) ||
        !["text/javascript", "application/javascript"].includes(blob.type.split(";")[0])) return createURL(blob);
    injected = true;
    const prefix = `
      {
        const NativeDate = Date;
        Date = class extends NativeDate {
          constructor(...args) { super(...(args.length ? args : [${frozen}])); }
          static now() { return ${frozen}; }
        };
        const emit = (bytes, started, transport) => self.postMessage({
          boundaryRead: { bytes, milliseconds: performance.now() - started, transport }
        });
        const syncRead = FileReaderSync.prototype.readAsArrayBuffer;
        FileReaderSync.prototype.readAsArrayBuffer = function(blob) {
          const started = performance.now();
          while (performance.now() - started < ${delay}) {}
          const result = syncRead.call(this, blob);
          if (result.byteLength !== blob.size) throw new Error("Short legacy host read");
          emit(result.byteLength, started, "sync");
          return result;
        };
        const asyncRead = Blob.prototype.arrayBuffer;
        Blob.prototype.arrayBuffer = async function() {
          const started = performance.now();
          if (${delay} > 0) await new Promise(resolve => setTimeout(resolve, ${delay}));
          const result = await asyncRead.call(this);
          if (result.byteLength !== this.size) throw new Error("Short legacy host read");
          emit(result.byteLength, started, "async");
          return result;
        };
      }\n`;
    return createURL(new Blob([prefix, blob], { type: blob.type }));
  });
  return () => expect(injected).toBe(true);
}

async function measuredWorker(reads: ReadMetric[], delay: number, messages: WorkerCounts, readAhead = false) {
  const NativeWorker = Worker;
  let executionMs: number | undefined;
  let readId: number | undefined;
  let cacheStats: ReadAheadStats | undefined;
  vi.stubGlobal("Worker", class extends NativeWorker {
    constructor(url: string | URL, options?: WorkerOptions) {
      super(url, { ...options, name: `c2pa-benchmark-delay-${delay}-${readAhead ? "read-ahead" : "plain"}` });
      this.addEventListener("message", (event: MessageEvent<unknown>) => {
        const value = event.data;
        if (typeof value === "object" && value !== null && "boundaryWorker" in value) {
          // Keep test telemetry out of the production protocol dispatcher.
          event.stopImmediatePropagation();
          const record = value.boundaryWorker;
          if (typeof record !== "object" || record === null ||
              !("id" in record) || record.id !== readId ||
              !("reads" in record) || !Array.isArray(record.reads) ||
              !("delayMs" in record) || record.delayMs !== delay ||
              !("executionMs" in record) || typeof record.executionMs !== "number" ||
              !Number.isFinite(record.executionMs) || record.executionMs < 0 ||
              executionMs !== undefined) throw new Error("Invalid Worker measurement");
          reads.push(...record.reads.map(metric));
          if (readAhead) {
            if (!("readAhead" in record)) throw new Error("Missing read-ahead telemetry");
            assertReadAheadStats(record.readAhead);
            cacheStats = record.readAhead;
          } else if ("readAhead" in record) throw new Error("Unexpected read-ahead telemetry");
          executionMs = record.executionMs;
          messages.telemetry++;
        } else messages.fromWorker++;
      });
    }
    override postMessage(message: unknown, options?: Transferable[] | StructuredSerializeOptions): void {
      if (typeof message === "object" && message !== null && "id" in message &&
          "command" in message && typeof message.command === "object" && message.command !== null &&
          "method" in message.command && message.command.method === "read") {
        if (typeof message.id !== "number") throw new Error("Invalid performance operation ID");
        readId = message.id;
        executionMs = undefined;
        cacheStats = undefined;
      }
      messages.toWorker++;
      if (Array.isArray(options)) super.postMessage(message, options);
      else super.postMessage(message, options);
    }
  });
  try {
    const url = new URL(workerSrc, location.href);
    const started = performance.now();
    const runtime = await createWorker({ wasmSrc, workerSrc: url });
    return { runtime, initializationMs: performance.now() - started,
      executionMs: () => executionMs, readAhead: () => cacheStats };
  } finally { vi.unstubAllGlobals() }
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() });

async function compare(name: "unsigned" | "trusted-signed") {
  vi.spyOn(Date, "now").mockReturnValue(frozen);
  const stateStarted = performance.now();
  const state = await createC2pa({ wasmSrc });
  const stateInitializationMs = performance.now() - stateStarted;
  try {
    let asset: Blob;
    if (name === "unsigned") asset = await (await fetch(unsignedSrc)).blob();
    else {
      const key = await crypto.subtle.importKey("pkcs8",
        bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, "")),
        { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
      const signer: Signer = {
        alg: "es256", certs: [bytes(fixtures.cert)],
        async sign(data) {
          return new Uint8Array(await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
        },
      };
      const builder = await Builder.fromDefinition(state, fixtures.definition);
      try {
        const output = await builder.sign(signer, "image/jpeg", new Blob([bytes(fixtures.source)]));
        asset = new Blob([new Uint8Array(output.asset)], { type: "image/jpeg" });
      } finally { await builder.free() }
    }
    const assetSha256 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", await asset.arrayBuffer())),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
    const runs: PerformanceRecord["runs"] = [];
    for (const mode of ["natural", "delay-0", "delay-2"] as const) {
      const delay = mode === "delay-2" ? 2 : 0;
      const legacyReads: ReadMetric[] = [];
      const stateReads: ReadMetric[] = [];
      const workerReads: ReadMetric[] = [];
      const legacyMessages = counts();
      const workerMessages = counts();
      const readAheadReads: ReadMetric[] = [];
      const readAheadMessages = counts();
      const worker = await measuredWorker(workerReads, delay, workerMessages);
      let buffered: Awaited<ReturnType<typeof measuredWorker>> | undefined;
      let legacy: Awaited<ReturnType<typeof createLegacy>> | undefined;
      try {
        buffered = await measuredWorker(readAheadReads, delay, readAheadMessages, true);
        const assertInjection = instrumentLegacy(legacyReads, delay, legacyMessages);
        const legacyStarted = performance.now();
        legacy = await createLegacy({ wasmSrc: legacyWasmSrc });
        const legacyInitializationMs = performance.now() - legacyStarted;
        assertInjection();
        const stateContext = new Context(settings);
        const legacyContext = new LegacyContext(settings);
        if (name === "trusted-signed") {
          const changed = new Uint8Array(await asset.arrayBuffer());
          changed[changed.length - 4] ^= 1;
          const tampered = new Blob([changed], { type: "image/jpeg" });
          const baseline = await WorkerReader.fromBlob(worker.runtime, "image/jpeg", tampered, stateContext);
          const candidate = await WorkerReader.fromBlob(buffered.runtime, "image/jpeg", tampered, stateContext);
          try {
            const report = await candidate!.json();
            expect(report).toEqual(await baseline!.json());
            expect(report.validation_state).toBe("Invalid");
            expect(report.validation_status?.some((s) => s.code === "assertion.dataHash.mismatch")).toBe(true);
          } finally { await baseline?.free(); await candidate?.free() }
        }
        for (const client of [worker.runtime, buffered.runtime])
          await expect(WorkerReader.fromBlob(client, "image/jpeg", new Blob([Uint8Array.of(1, 2)]), stateContext))
            .rejects.toThrow();
        let baselineProjection: unknown;
        const results: Record<Backend, Sample[]> = {
          legacy: [], "state-machine": [], "state-machine-worker": [], "state-machine-read-ahead": [],
        };
        const firstOperationMs: Partial<Record<Backend, number>> = {};
        for (let iteration = 0; iteration < samples + 2; iteration++) {
          const offset = iteration % backends.length;
          const order = [...backends.slice(offset), ...backends.slice(0, offset)];
          for (const backend of order) {
            const reads = backend === "legacy" ? legacyReads : backend === "state-machine" ? stateReads :
              backend === "state-machine-worker" ? workerReads : readAheadReads;
            const messages = backend === "legacy" ? legacyMessages : backend === "state-machine-worker" ? workerMessages :
              backend === "state-machine-read-ahead" ? readAheadMessages : counts();
            const activeWorker = backend === "state-machine-read-ahead" ? buffered : worker;
            Object.assign(messages, counts());
            reads.splice(0);
            const started = performance.now();
            const reader = backend === "legacy"
              ? await LegacyReader.fromBlob(legacy, "image/jpeg", asset, legacyContext)
              : backend === "state-machine"
                ? await Reader.fromBlob(state, "image/jpeg", measuredBlob(asset, reads, delay), stateContext)
                : await WorkerReader.fromBlob(activeWorker.runtime, "image/jpeg", asset, stateContext);
            const durationMs = performance.now() - started;
            const captured = reads.slice();
            const capturedMessages = { ...messages };
            try {
              if (name === "unsigned") expect(reader).toBeNull();
              else {
                expect(reader).not.toBeNull();
                expect((await reader!.manifestStore()).validation_state).toBe("Trusted");
                expect(await reader!.activeLabel()).toBe(fixtures.definition.label);
                if (backend === "state-machine-worker") baselineProjection = await reader!.json();
                else if (backend === "state-machine-read-ahead") expect(await reader!.json()).toEqual(baselineProjection);
              }
            } finally { await reader?.free() }
            expect(captured.length).toBeGreaterThan(0);
            const totalBytes = captured.reduce((total, read) => total + read.bytes, 0);
            const sample: Sample = {
              durationMs, hostServiceMs: captured.reduce((total, read) => total + read.milliseconds, 0),
              calls: captured.length, bytesRequested: totalBytes, bytesReturned: totalBytes,
              readSizes: captured.map((read) => read.bytes),
              transports: {
                sync: captured.filter((read) => read.transport === "sync").length,
                async: captured.filter((read) => read.transport === "async").length,
              },
              messages: capturedMessages,
              ...(backend !== "legacy" && backend !== "state-machine"
                ? { workerExecutionMs: activeWorker.executionMs() } : {}),
              ...(backend === "state-machine-read-ahead" ? { readAhead: activeWorker.readAhead() } : {}),
            };
            if (backend === "state-machine-worker" || backend === "state-machine-read-ahead") {
              expect(sample.messages).toEqual({ toWorker: 1, fromWorker: 1, telemetry: 1 });
              expect(Number.isFinite(sample.workerExecutionMs)).toBe(true);
              expect(captured.every((read) => read.transport === "async")).toBe(true);
              expect(activeWorker.runtime.liveResources).toBe(0);
            } else if (backend === "legacy") {
              expect(sample.messages.toWorker).toBeGreaterThan(0);
              expect(sample.messages.fromWorker).toBeGreaterThan(0);
              expect(sample.messages.telemetry).toBe(sample.calls);
            } else expect(sample.messages).toEqual(counts());
            if (backend === "state-machine-read-ahead") {
              expect(sample.readAhead).toBeDefined();
              expect(sample.calls).toBe(name === "unsigned" ? 1 : 4);
              expect(sample.bytesReturned).toBe(name === "unsigned" ? 4096 : asset.size + 4072);
              expect(sample.readAhead!.maxResidentBytes).toBe(4096);
              expect(sample.readAhead!.fills).toBe(1);
              expect(sample.readAhead!.hits).toBe(name === "unsigned" ? 9 : 11);
              expect(sample.readAhead!.bypasses).toBe(name === "unsigned" ? 0 : 3);
            } else {
              expect(sample.calls).toBe(backend === "legacy" ? 1 : name === "unsigned" ? 10 : 15);
              expect(sample.bytesReturned).toBe(
                backend === "legacy" ? asset.size : name === "unsigned" ? 38 : asset.size + 38);
            }
            if (iteration === 0) firstOperationMs[backend] = durationMs;
            if (iteration >= 2) results[backend].push(sample);
          }
        }
        for (const backend of backends) {
          const baseline = results[backend][0];
          for (const sample of results[backend]) {
            expect(sample.calls).toBe(baseline.calls);
            expect(sample.bytesRequested).toBe(baseline.bytesRequested);
            expect(sample.readSizes).toEqual(baseline.readSizes);
          }
        }
        expect(results["state-machine-worker"][0].readSizes).toEqual(results["state-machine"][0].readSizes);
        for (const sample of results["state-machine-read-ahead"])
          expect(sample.readAhead!.logicalReadSizes).toEqual(results["state-machine-worker"][0].readSizes);
        runs.push({ mode, delayMs: delay, legacyInitializationMs,
          workerInitializationMs: worker.initializationMs, readAheadInitializationMs: buffered.initializationMs,
          firstOperationMs, results });
      } finally {
        legacy?.dispose();
        worker.runtime.dispose();
        buffered?.runtime.dispose();
        expect(worker.runtime.liveResources).toBe(0);
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
        vi.spyOn(Date, "now").mockReturnValue(frozen);
      }
    }
    for (const run of runs.slice(1)) {
      for (const backend of backends) {
        expect(run.results[backend][0].readSizes).toEqual(runs[0].results[backend][0].readSizes);
      }
    }
    console.log(`BOUNDARY_PERFORMANCE ${JSON.stringify({
      schema: 3, case: name, assetBytes: asset.size, assetSha256,
      userAgent: navigator.userAgent, stateInitializationMs, runs,
    })}`);
  } finally { state.dispose(); expect(state.liveResources).toBe(0) }
}

test("host-boundary unsigned JPEG comparison", async () => { await compare("unsigned") }, 120_000);
test("host-boundary trusted signed JPEG comparison", async () => { await compare("trusted-signed") }, 120_000);
