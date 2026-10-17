import { open, rename, unlink } from "node:fs/promises";
import { memoryOutput, range } from "../shared/drive.mjs";

export async function removeTemporary(path) {
  try { await unlink(path) }
  catch (error) { if (error.code !== "ENOENT") throw error }
}

export async function openOutput(destination) {
  if (destination === undefined) return memoryOutput();
  const file = await open(destination.temporary, "wx+", 0o600);
  let length = 0;
  let closed = false;
  let committed = false;
  return {
    get length() { return length },
    async read(start, len) {
      range(start, len, length);
      const bytes = Buffer.allocUnsafe(len);
      let offset = 0;
      while (offset < len) {
        const { bytesRead } = await file.read(bytes, offset, len - offset, start + offset);
        if (!bytesRead) throw new Error("short output read");
        offset += bytesRead;
      }
      return bytes;
    },
    async write(start, bytes) {
      range(start, bytes.length, Number.MAX_SAFE_INTEGER);
      let offset = 0;
      while (offset < bytes.length) {
        const { bytesWritten } = await file.write(bytes, offset, bytes.length - offset, start + offset);
        if (!bytesWritten) throw new Error("short output write");
        offset += bytesWritten;
      }
      length = Math.max(length, start + bytes.length);
    },
    async finish() {
      await file.truncate(length);
      await file.close();
      closed = true;
      await rename(destination.temporary, destination.path);
      committed = true;
      return { path: destination.path, outputBytes: length };
    },
    async close() {
      try { if (!closed) { await file.close(); closed = true } }
      finally { if (!committed) await removeTemporary(destination.temporary) }
    },
  };
}
