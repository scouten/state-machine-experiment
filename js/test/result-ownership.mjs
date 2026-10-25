import { serve, protocol } from "../src/shared/service.mjs";

function check(value, message) { if (!value) throw new Error(message) }

export async function resultOwnershipContract() {
  for (const size of [0, 3, 5001]) {
    let dispatch;
    let complete;
    let failed;
    let step = 0;
    let closed = false;
    const delivered = new Promise((resolve, reject) => { complete = resolve; failed = reject });
    serve({
      onMessage(callback) { dispatch = callback },
      post(message, transfer = []) {
        const moved = structuredClone(message, { transfer });
        if (message.ok) {
          check(transfer.length === 1 && message.value.asset.byteLength === 0, "result was cloned, not transferred");
          complete(moved.value);
        } else if (message.error) failed(new Error(message.error.message));
      },
    }, {
      createBuild: () => ({
        advance: () => step++ ? { done: true } : { requests: size === 5001 ? [
          { id: 1, kind: "write", stream: "output", offset: 0, bytes: new Uint8Array(3).fill(42) },
          { id: 2, kind: "write", stream: "output", offset: 5000, bytes: new Uint8Array([42]) },
        ] : [{ id: 1, kind: "write", stream: "output", offset: 0, bytes: new Uint8Array(size).fill(42) }] },
        fulfill() {}, finish: () => ({}), close() { closed = true },
      }),
    });
    dispatch({ protocol, id: 1, method: "build", asset: new Uint8Array(), definition: "{}", certs: [] });
    const result = await delivered;
    check(closed, "session not closed before delivery");
    check(result.asset.length === size && result.asset.buffer.byteLength === size, "result exposed spare capacity");
    check(result.asset.every((byte, i) => byte ===
      (size === 5001 && i >= 3 && i < 5000 ? 0 : 42)), "transferred result changed or exposed stale gaps");
  }
  return ["output transferred", "exact backing length", "empty/small/grown output", "byte equality", "session cleanup"];
}
