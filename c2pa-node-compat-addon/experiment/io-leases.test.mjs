// Run only with npm run test:leases on standard Node (not sandboxed Electron).
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir, open, readFile, rm, writeFile } from "node:fs/promises";
import { setImmediate } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const native = createRequire(import.meta.url)("../index.node");
const allocate = native.leaseProbeAllocate;
assert.equal(typeof allocate, "function", "build with io-lease-experiment");
assert.equal(typeof global.gc, "function", "run Node with --expose-gc");

// Keep fixtures inside this worktree, never in an OS temporary directory.
const directory = fileURLToPath(new URL(`./io-fixtures-${process.pid}/`, import.meta.url));
const payload = Buffer.from("native file I/O lease probe\n".repeat(4096));

async function collected(tracker) {
  for (let i = 0; i < 200; i++) {
    global.gc();
    await setImmediate();
    if (native.leaseProbeFinalized(tracker) === 1) return;
  }
  assert.fail("external Vec finalizer did not run within 200 GC turns");
}

test("Node external-buffer capability and copy boundaries", async (t) => {
  await mkdir(directory);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const input = `${directory}/input`;
  await writeFile(input, payload);

  await t.test("fs.read fills the same native allocation; immutable handoff copies", async () => {
    const file = await open(input, "r");
    try {
      const lease = allocate(payload.length);
      assert.equal(lease.allocationPointer, lease.viewPointer);
      assert.equal(lease.copiedBytes, 0);
      const { bytesRead } = await file.read(lease.buffer, 0, payload.length, 0);
      assert.equal(bytesRead, payload.length);
      assert.equal(native.leaseProbePointer(lease.buffer), lease.allocationPointer);
      assert.deepEqual(lease.buffer, payload);

      const snapshot = native.leaseProbeCopyIn(lease.buffer, bytesRead);
      assert.equal(snapshot.sourcePointer, lease.allocationPointer);
      assert.notEqual(snapshot.allocationPointer, snapshot.sourcePointer);
      assert.equal(snapshot.vecPointer, snapshot.allocationPointer);
      assert.equal(snapshot.copiedBytes, bytesRead);
      const alias = new Uint8Array(lease.buffer.buffer, lease.buffer.byteOffset, bytesRead);
      alias.fill(0);
      assert.deepEqual(native.leaseProbeObserve(snapshot.bytes), payload);
      assert.ok(lease.buffer.every((byte) => byte === 0));
      t.diagnostic(`read: external pointer equal; immutable handoff copies ${bytesRead} bytes`);
    } finally {
      await file.close();
    }
  });

  await t.test("partial EOF initializes the tail and snapshots only the actual prefix", async () => {
    const file = await open(input, "r");
    try {
      const lease = allocate(payload.length + 19);
      const { bytesRead } = await file.read(lease.buffer, 0, lease.buffer.length, 0);
      assert.equal(bytesRead, payload.length);
      assert.ok(lease.buffer.subarray(bytesRead).every((byte) => byte === 0));
      const snapshot = native.leaseProbeCopyIn(lease.buffer, bytesRead);
      assert.deepEqual(native.leaseProbeObserve(snapshot.bytes), payload);
      const eof = await file.read(lease.buffer, 0, lease.buffer.length, bytesRead);
      assert.equal(eof.bytesRead, 0);
      assert.throws(() => native.leaseProbeCopyIn(lease.buffer, -1), RangeError);
      assert.throws(() => native.leaseProbeCopyIn(lease.buffer, 0.5), RangeError);
      assert.throws(() => native.leaseProbeCopyIn(lease.buffer, Infinity), RangeError);
      assert.throws(() => native.leaseProbeCopyIn(lease.buffer, lease.buffer.length + 1), RangeError);
    } finally {
      await file.close();
    }
  });

  await t.test("structuredClone transfer cannot revoke external-buffer aliases", () => {
    const lease = allocate(32);
    const backing = lease.buffer.buffer;
    const alias = lease.buffer.subarray(1);
    assert.throws(() => structuredClone(backing, { transfer: [backing] }), {
      name: "DataCloneError",
    });
    assert.equal(backing.byteLength, 32);
    alias[0] = 0x5a;
    assert.equal(lease.buffer[1], 0x5a);
    assert.equal(native.leaseProbePointer(lease.buffer), lease.allocationPointer);
  });

  await t.test("fs.write uses an external Vec, but immutable Bytes need staging", async () => {
    const snapshot = native.leaseProbeCopyIn(payload, payload.length);
    const lease = native.leaseProbeCopyOut(snapshot.bytes);
    assert.equal(lease.sourcePointer, snapshot.allocationPointer);
    assert.notEqual(lease.allocationPointer, lease.sourcePointer);
    assert.equal(lease.viewPointer, lease.allocationPointer);
    assert.equal(lease.copiedBytes, payload.length);
    const output = `${directory}/output`;
    const file = await open(output, "w");
    try {
      let written = 0;
      while (written < lease.buffer.length) {
        // Exercise retained slices and multiple writes, not whole-buffer-only I/O.
        const chunk = lease.buffer.subarray(written, written + 8191);
        const { bytesWritten } = await file.write(chunk, 0, chunk.length, written);
        assert.ok(bytesWritten > 0);
        written += bytesWritten;
      }
    } finally {
      await file.close();
    }
    assert.deepEqual(await readFile(output), payload);
    lease.buffer.fill(0);
    assert.deepEqual(native.leaseProbeObserve(snapshot.bytes), payload);
    t.diagnostic(`write: external pointer equal; Bytes staging copies ${payload.length} bytes`);
  });

  await t.test("abandoned allocations finalize exactly once", async () => {
    let lease = allocate(32);
    const tracker = lease.tracker;
    lease = null;
    await collected(tracker);
    global.gc();
    await setImmediate();
    assert.equal(native.leaseProbeFinalized(tracker), 1);
  });

  await t.test("disposing the owner cannot free a retained JS alias", async () => {
    let lease = allocate(32);
    const tracker = lease.tracker;
    let alias = lease.buffer.subarray(3);
    lease = null;
    global.gc();
    await setImmediate();
    assert.equal(native.leaseProbeFinalized(tracker), 0);
    alias.fill(0x5a);
    assert.equal(alias[0], 0x5a);
    alias = null;
    await collected(tracker);
  });

  await t.test("an in-flight fs.read survives disposal of the experiment owner", async () => {
    const file = await open(input, "r");
    let tracker;
    try {
      let lease = allocate(payload.length);
      tracker = lease.tracker;
      let pending = file.read(lease.buffer, 0, payload.length, 0);
      lease = null;
      global.gc();
      assert.equal(native.leaseProbeFinalized(tracker), 0);
      let result = await pending;
      assert.equal(result.bytesRead, payload.length);
      assert.deepEqual(result.buffer, payload);
      pending = null;
      result = null;
    } finally {
      await file.close();
    }
    await collected(tracker);
  });

  await t.test("an in-flight fs.write survives disposal of the experiment owner", async () => {
    const snapshot = native.leaseProbeCopyIn(payload, payload.length);
    const output = `${directory}/in-flight-output`;
    const file = await open(output, "w");
    let tracker;
    try {
      let lease = native.leaseProbeCopyOut(snapshot.bytes);
      tracker = lease.tracker;
      let pending = file.write(lease.buffer, 0, payload.length, 0);
      lease = null;
      global.gc();
      assert.equal(native.leaseProbeFinalized(tracker), 0);
      let result = await pending;
      assert.equal(result.bytesWritten, payload.length);
      assert.deepEqual(result.buffer, payload);
      pending = null;
      result = null;
    } finally {
      await file.close();
    }
    assert.deepEqual(await readFile(output), payload);
    await collected(tracker);
  });

  await t.test("allocation bounds reject malformed and empty requests", () => {
    for (const length of [0, -1, 0.5, NaN, Infinity, 16 * 1024 * 1024 + 1]) {
      assert.throws(() => allocate(length), RangeError);
    }
  });
});
