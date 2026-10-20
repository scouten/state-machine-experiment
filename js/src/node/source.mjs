import { open } from "node:fs/promises";
import { constants } from "node:fs";
import { source, range } from "../shared/drive.mjs";

export async function openSource(asset) {
  if (!asset || typeof asset.path !== "string") return source(asset);
  const file = await open(asset.path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || !Number.isSafeInteger(stat.size))
      throw new Error("asset path must identify a regular file with a safe integer length");
    return {
      length: stat.size,
      async read(start, len) {
        range(start, len, stat.size);
        const bytes = Buffer.allocUnsafe(len);
        let offset = 0;
        while (offset < len) {
          const { bytesRead } = await file.read(bytes, offset, len - offset, start + offset);
          if (bytesRead === 0) throw new Error("short asset read: source file changed");
          offset += bytesRead;
        }
        return bytes;
      },
      close: () => file.close(),
    };
  } catch (error) {
    await file.close();
    throw error;
  }
}
