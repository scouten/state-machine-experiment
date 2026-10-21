import assert from "node:assert/strict";
import test from "node:test";
import { build } from "../src/shared/drive.mjs";

function adapter(request, onReply = () => {}) {
  let issued = false;
  let closed = false;
  return {
    createBuild() {
      return {
        advance() {
          if (issued) return { done: true };
          issued = true;
          return { done: false, requests: [request] };
        },
        fulfill(...reply) { onReply(...reply) },
        finish() { return {} },
        close() { closed = true },
      };
    },
    get closed() { return closed },
  };
}

test("copyRange moves source bytes locally with a metadata-only acknowledgement", async () => {
  const replies = [];
  const host = adapter({ id: 1, kind: "copyRange", start: 1, len: 2, offset: 3 },
    (...reply) => replies.push(reply));
  const result = await build(host, new Uint8Array([1, 2, 3]), "{}", [], () => {});
  assert.deepEqual(result.asset, new Uint8Array([0, 0, 0, 2, 3]));
  assert.deepEqual(replies, [[1, "copied"]]);
  assert.equal(result.stats.copies, 1);
  assert.equal(result.stats.copiedBytes, 2);
  assert.equal(result.stats.reads, 0);
  assert.equal(result.stats.writtenBytes, 0);
  assert.ok(host.closed);
});

test("malformed, overflowing, and short-source copy ranges never acknowledge success", async () => {
  for (const values of [
    { start: 2, len: 2, offset: 0 },
    { start: -1, len: 1, offset: 0 },
    { start: 0, len: 1.5, offset: 0 },
    { start: 0, len: 1, offset: Number.MAX_SAFE_INTEGER },
    { start: Number.MAX_SAFE_INTEGER, len: 1, offset: 0 },
  ]) {
    let acknowledged = false;
    const host = adapter({ id: 1, kind: "copyRange", ...values },
      () => { acknowledged = true });
    await assert.rejects(build(host, new Uint8Array(3), "{}", [], () => {}), /invalid asset range/);
    assert.equal(acknowledged, false);
    assert.ok(host.closed);
  }
});
