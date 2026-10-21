import { open } from "node:fs/promises";
import { openSource, range, snapshotAsset } from "../shared/source.mjs";

/** Node also accepts `{path: string}`; files must stay unchanged until settled. */
export function snapshotNodeAsset(asset) {
  if (asset instanceof Uint8Array || (typeof Blob !== "undefined" && asset instanceof Blob))
    return snapshotAsset(asset);
  if (asset && typeof asset.path === "string") return { path: asset.path };
  return snapshotAsset(asset);
}

/** Opens only when its queued operation starts, and closes when it settles. */
export async function openNodeSource(asset, openFile = open) {
  if (!asset || typeof asset.path !== "string") return openSource(asset);
  const file = await openFile(asset.path, "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || !Number.isSafeInteger(stat.size)) throw new Error("invalid asset file");
    return {
      length: stat.size,
      async getLength() {
        const current = await file.stat();
        if (current.size !== stat.size) throw new Error("asset file length changed");
        return current.size;
      },
      async read(start, len) {
        range(start, len, stat.size);
        const bytes = new Uint8Array(len);
        let offset = 0;
        while (offset < len) {
          const { bytesRead } = await file.read(bytes, offset, len - offset, start + offset);
          if (!bytesRead) throw new Error("short asset read");
          offset += bytesRead;
        }
        return bytes;
      },
      close: () => file.close(),
    };
  } catch (error) {
    try { await file.close() }
    catch (cleanup) {
      throw new AggregateError([error, cleanup],
        `${String(error)}; source cleanup failed: ${String(cleanup)}`);
    }
    throw error;
  }
}
