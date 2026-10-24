// Read contract shared by the Node and browser runners: both environments
// must produce identical reports and request counters for the same fixtures.
function check(value, message) { if (!value) throw new Error(message) }
function equal(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(message);
}
async function rejects(promise, pattern) {
  try { await promise }
  catch (error) {
    check(pattern.test(`${error.name}: ${error.message}`), `unexpected error: ${error}`);
    return;
  }
  throw new Error("expected rejection");
}

// Executed unchanged against Node and browser clients, with real native/Wasm code.
export async function contract(createClient, small, large, fixture) {
  const options = { settings: fixture.settings, now: fixture.now };
  const client = createClient();
  try {
    const expected = fixture.files.small;
    const snapshot = new Uint8Array(small);
    const pending = client.read(snapshot, options);
    snapshot.fill(0);
    const result = await pending;
    equal(result.report, expected.report, "full report differs from direct native host");
    equal(result.stats, expected.stats, "session request accounting differs");
    check(snapshot.byteLength === small.length, "caller buffer was detached");
    const owned = new Uint8Array(small);
    const transferred = client.read(owned, { ...options, ownership: "transfer" });
    check(owned.byteLength === 0, "transfer did not consume input before awaiting");
    equal((await transferred).report, expected.report, "transferred input report changed");
    const subview = new Uint8Array(small.length + 2).subarray(1, small.length + 1);
    subview.set(small);
    await rejects(client.read(subview, { ...options, ownership: "transfer" }), /full ArrayBuffer/);
    check(subview.byteLength === small.length, "rejected transfer detached a subview");
    await rejects(client.read(small, { ...options, ownership: "invalid" }), /ownership/);
    const wasm = new WebAssembly.Memory({ initial: 1 });
    await rejects(client.read(new Uint8Array(wasm.buffer), { ...options, ownership: "transfer" }), /./);
    check(wasm.buffer.byteLength === 65536, "rejected transfer detached Wasm storage");
    equal((await client.read(new Uint8Array([255, 216, 255, 217]), options)).report, null, "unsigned must return null");
    await rejects(client.read(small, { settings: { verify: { ocsp_fetch: "invalid" } }, now: fixture.now }), /BadParam|invalid|expected/i);
    const malformed = new Uint8Array(small);
    malformed[0] = 0;
    await rejects(client.read(malformed, options), /./);
    const changed = new Uint8Array(large);
    changed[changed.length - 1] ^= 1;
    const damaged = await client.read(changed, options);
    check(damaged.report.validation_state === "Invalid", "tamper must be Invalid");
    const ordered = await Promise.all([client.read(small, options), client.read(large, options)]);
    equal(ordered[0].report, expected.report, "queued operation report changed");
    equal(ordered[1].report, fixture.files.large.report, "large report differs");
    const ownedLarge = new Uint8Array(large);
    const movedLarge = client.read(ownedLarge, { ...options, ownership: "transfer" });
    check(ownedLarge.byteLength === 0, "large input was not consumed");
    equal((await movedLarge).report, fixture.files.large.report, "large transferred input report changed");

    const samples = [];
    // Warmup and startup costs are separate from these repeated operations.
    for (let iteration = 0; iteration < 3; iteration++) {
      let ticks = 0;
      let previous = performance.now();
      let maxGapMs = 0;
      const timer = setInterval(() => {
        const now = performance.now();
        maxGapMs = Math.max(maxGapMs, now - previous);
        previous = now;
        ticks++;
      }, 1);
      const started = performance.now();
      try {
        const result = await client.read(large, options);
        const totalMs = performance.now() - started;
        maxGapMs = Math.max(maxGapMs, performance.now() - previous);
        equal(result.report, fixture.files.large.report, "repeated report differs");
        equal(result.stats, fixture.files.large.stats, "repeated request bytes differ");
        check(ticks > 0, "application tasks made no progress during Worker operation");
        samples.push({ totalMs, workerMs: result.workerMs, ticks, maxGapMs, stats: result.stats });
      } finally { clearInterval(timer) }
    }
    // Isolates must own separate native sessions; disposing one cannot kill another.
    const other = createClient();
    try {
      const abandoned = client.read(large, options);
      const rejection = rejects(abandoned, /disposed/);
      await client.dispose();
      await rejection;
      equal((await other.read(small, options)).report, expected.report, "other Worker affected by disposal");
    } finally { await other.dispose() }
    await rejects(client.read(small, options), /disposed/);
    return { samples, checks: ["full report", "exact request bytes", "input snapshot/no detach",
      "owned input transfer", "subview and Wasm transfer rejection",
      "unsigned null", "settings error", "malformed error/retry", "tamper Invalid",
      "queued operations", "application task progress", "pending disposal", "Worker isolation"] };
  } finally { await client.dispose() }
}
