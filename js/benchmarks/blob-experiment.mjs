// Shared Blob-versus-bytes experiment: signs and reads small and large assets
// through each input form against one client, recording timings and heap use.
// Browser and Node drivers supply `create`, `input`, `sign` and `meter`.
import { validateReport } from "./sdk-benchmark.mjs";

function check(value, message) { if (!value) throw new Error(message) }
const pause = () => new Promise((resolve) => setTimeout(resolve, 100));

/** Runs the experiment against the supplied client factory and returns its samples. */
export async function experiment({ create, input, small, definition, sign, meter }) {
  const samples = [];
  const reference = await create("bytes");
  const control = await create("existing");
  const expected = await reference.read(input.signedBytes);
  validateReport(expected.report, definition);
  let buildStats;
  for (const variant of ["bytes", "blob", "file", "existing"]) {
    console.log(`source experiment: ${variant}`);
    const source = await input.load(variant, false);
    const signed = await input.load(variant, true);
    for (const operation of ["read", "sign"]) {
      for (const lifecycle of ["fresh", "reused"]) {
        let adapter;
        try {
          for (let iteration = 0; iteration < 3; iteration++) {
            if (!adapter) {
              adapter = await create(variant);
              await adapter.read(small);
            }
            await pause();
            const baseline = await meter.start();
            let value;
            let memory;
            let calls = 0;
            const started = performance.now();
            let pending = operation === "read" ? adapter.read(signed)
              : adapter.sign(source, definition, async (bytes) => { calls++; return sign(bytes) });
            const setupMs = performance.now() - started;
            try {
              value = await pending;
              const totalMs = performance.now() - started;
              memory = await meter.stop();
              if (operation === "read") {
                validateReport(value.report, definition);
                if (variant !== "existing") {
                  check(JSON.stringify(value.report) === JSON.stringify(expected.report), "report differs by source");
                  check(JSON.stringify(value.stats) === JSON.stringify(expected.stats), "read accounting differs");
                  check(value.stats.maxReadBytes <= 65536, "unbounded source read");
                }
              } else {
                check(calls === 1, "signer must run once");
                validateReport((await reference.read(value.asset)).report, definition);
                validateReport((await control.read(value.asset)).report, definition);
                await control.cleanup?.();
                if (variant !== "existing") {
                  buildStats ??= value.stats;
                  check(JSON.stringify(value.stats) === JSON.stringify(buildStats), "build accounting differs by source");
                }
              }
              samples.push({ variant, operation, lifecycle, iteration, setupMs, totalMs,
                baseline, memory, outputBytes: value.asset?.length, stats: value.stats });
            } finally {
              await meter.stop();
              await adapter.cleanup?.();
              value = undefined;
              pending = undefined;
            }
            await pause();
            samples.at(-1).quiescent = await meter.current();
            if (lifecycle === "fresh") {
              await adapter.close();
              adapter = undefined;
            }
          }
        } finally { await adapter?.close() }
      }
    }
  }
  try {
    const changed = input.signedBytes.slice();
    changed[changed.length - 1] ^= 1;
    for (const reader of [reference, control]) {
      check((await reader.read(changed)).report.validation_state === "Invalid", "tampering accepted");
      await reader.cleanup?.();
    }
  } finally { await reference.close(); await control.close() }
  return { samples, checks: ["full report/source accounting parity", "64 KiB maximum read",
    "every sign cross-validated Trusted", "single signer call", "tamper rejection by both readers"] };
}
