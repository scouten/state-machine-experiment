// How busy does reading a big asset keep the JS thread?
//
// Builds a large file (a signed JPEG followed by padding, so the engine
// really does hash every byte), reads it while a 1 ms timer watches the
// event loop, and reports the worst gap between ticks. The padding means
// the hard binding is reported as a mismatch; the work done is the same.

import { mkdtempSync, openSync, writeSync, closeSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";

import { Reader } from "../index.mjs";

const MB = Number(process.argv[2] ?? 256);
const dir = mkdtempSync(join(tmpdir(), "c2pa-lag-"));
const path = join(dir, "big.jpg");
const jpeg = readFileSync(new URL("../../contentauth-c2pa-reader/tests/fixtures/C.jpg", import.meta.url));

const fd = openSync(path, "w");
writeSync(fd, jpeg);
const pad = Buffer.alloc(1 << 20);
for (let i = 0; i < MB; i++) writeSync(fd, pad);
closeSync(fd);

for (const concurrency of [1, 8]) {
  const histogram = monitorEventLoopDelay({ resolution: 1 });
  histogram.enable();
  const started = performance.now();
  const reader = await Reader.fromAsset({ path }, null, { concurrency });
  const elapsed = performance.now() - started;
  histogram.disable();

  console.log(
    `${MB} MB, concurrency ${String(concurrency).padEnd(2)}: ${(elapsed / 1000).toFixed(2)} s, ` +
      `${((MB / elapsed) * 1000).toFixed(0)} MB/s, event-loop delay ` +
      `p50 ${(histogram.percentile(50) / 1e6).toFixed(1)} ms, ` +
      `p99 ${(histogram.percentile(99) / 1e6).toFixed(1)} ms, ` +
      `max ${(histogram.max / 1e6).toFixed(1)} ms  [${reader.json().validation_state}]`,
  );
}

rmSync(dir, { recursive: true });
