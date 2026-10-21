// Capability experiment, not a production source or Rust lease implementation.
// Dedicated Workers are required for OPFS synchronous access handles.
let stage = "BYOB and transfer checks";
function check(value, message) { if (!value) throw new Error(message) }

async function rejects(action, name) {
  try { await action() }
  catch (error) {
    check([name].flat().includes(error.name), `expected ${name}, got ${error}`);
    return `${error.name}: ${error.message}`;
  }
  throw new Error(`expected ${name}`);
}

function stream() {
  return new ReadableStream({
    type: "bytes",
    pull(controller) {
      controller.byobRequest.view[0] = 42;
      controller.byobRequest.respond(1);
      controller.close();
    },
  });
}

function readExactly(handle, destination, at) {
  let filled = 0;
  while (filled < destination.length) {
    const count = handle.read(destination.subarray(filled), { at: at + filled });
    if (!Number.isInteger(count) || count <= 0 || count > destination.length - filled)
      throw new Error("short or invalid OPFS read");
    filled += count;
  }
}

async function explore() {
  const memory = new WebAssembly.Memory({ initial: 2 });
  const ordinary = stream().getReader({ mode: "byob" });
  try {
    const view = new Uint8Array(8);
    const { value } = await ordinary.read(view);
    check(view.byteLength === 0 && value[0] === 42, "ordinary BYOB did not transfer storage");
  } finally { ordinary.releaseLock() }

  const byob = stream().getReader({ mode: "byob" });
  let byobError;
  try {
    byobError = await rejects(() => byob.read(new Uint8Array(memory.buffer, 23, 65536)), "TypeError");
    check(memory.buffer.byteLength === 131072, "BYOB detached Wasm storage");
  } finally { await byob.cancel(); byob.releaseLock() }
  const transferError = await rejects(() => structuredClone(memory.buffer, { transfer: [memory.buffer] }),
    ["DataCloneError", "TypeError"]);
  check(memory.buffer.byteLength === 131072, "transfer detached Wasm storage");

  stage = "OPFS root";
  const root = await navigator.storage.getDirectory();
  const name = `read-lease-proof-${crypto.randomUUID()}`;
  let handle;
  try {
    stage = "OPFS file creation";
    const file = await root.getFileHandle(name, { create: true });
    stage = "OPFS synchronous access handle";
    handle = await file.createSyncAccessHandle();
    stage = "OPFS fixture write";
    const source = Uint8Array.from({ length: 1024 * 1024 + 17 }, (_, i) => (i * 31 + 7) & 255);
    let written = 0;
    while (written < source.length) {
      const count = handle.write(source.subarray(written), { at: written });
      check(count > 0 && count <= source.length - written, "invalid OPFS setup write");
      written += count;
    }
    handle.flush();
    let stagedCopyBytes = 0;
    let directReadBytes = 0;
    for (const staged of [true, false]) {
      stage = staged ? "OPFS staged reads" : "OPFS direct Wasm reads";
      for (let at = 0; at < source.length; at += 65536) {
        const len = Math.min(65536, source.length - at);
        const target = new Uint8Array(memory.buffer, 23, len);
        if (staged) {
          const intermediate = new Uint8Array(len);
          readExactly(handle, intermediate, at);
          target.set(intermediate);
          stagedCopyBytes += len;
        } else {
          readExactly(handle, target, at);
          directReadBytes += len;
        }
        check(target.every((byte, i) => byte === source[at + i]), "file-to-Wasm bytes changed");
      }
    }
    // Exact-read policy must reject EOF rather than seal zero-filled trailing bytes.
    await rejects(() => readExactly(handle, new Uint8Array(memory.buffer, 23, 2), source.length - 1),
      "Error");
    readExactly(handle, new Uint8Array(memory.buffer, 23, 0), source.length);
    const stale = new Uint8Array(memory.buffer, 23, 19);
    memory.grow(1);
    check(stale.byteLength === 0, "growth did not detach old view");
    readExactly(handle, new Uint8Array(memory.buffer, 23, 19), 7);
    check(new Uint8Array(memory.buffer, 23, 19).every((byte, i) => byte === source[7 + i]),
      "direct read after growth changed");
    check(stagedCopyBytes === source.length && directReadBytes === source.length, "copy accounting changed");
    return {
      checks: ["ordinary BYOB transfers storage", "Wasm BYOB rejected", "Wasm transfer rejected",
        "OPFS fills Wasm memory directly", "staged/direct byte equality", "EOF rejected",
        "zero-length read", "fresh destination after memory.grow", "OPFS handle/file cleanup"],
      byobError, transferError, inputBytes: source.length, stagedCopyBytes, directReadBytes,
      directStagingCopyBytes: 0,
      scope: "Actual browser I/O into WebAssembly.Memory; not yet Rust-owned Vec leases or SDK integration. Copy counts exclude OS/browser internals and fixture setup; no peak-memory/timing claim.",
    };
  } finally {
    try { handle?.close() }
    finally { await root.removeEntry(name) }
  }
}

self.onmessage = async () => {
  try { self.postMessage({ ok: true, value: await explore() }) }
  catch (error) { self.postMessage({ ok: false, error: `${stage}: ${error.name}: ${error.message}` }) }
};
