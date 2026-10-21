/** Immutable browser inputs need no eager byte snapshot. Byte arrays still do. */
export function snapshotAsset(asset) {
  if (asset instanceof Uint8Array) return new Uint8Array(asset);
  if (typeof Blob !== "undefined" && asset instanceof Blob) return asset;
  throw new TypeError("asset must be Uint8Array or Blob");
}

/** Checks the requested range before any backing-store access. */
export function range(start, len, length) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(len) ||
      !Number.isSafeInteger(start + len) || start < 0 || len < 0 || start + len > length)
    throw new Error("invalid asset range");
}

/** Worker-local source; only the requested Blob slice becomes an ArrayBuffer. */
export function openSource(asset) {
  const blob = typeof Blob !== "undefined" && asset instanceof Blob;
  if (!blob && !(asset instanceof Uint8Array))
    throw new TypeError("asset must be Uint8Array or Blob");
  const length = blob ? asset.size : asset.length;
  return {
    length,
    async read(start, len) {
      range(start, len, length);
      const bytes = blob
        ? new Uint8Array(await asset.slice(start, start + len).arrayBuffer())
        : asset.subarray(start, start + len);
      if (bytes.length !== len) throw new Error("short asset read");
      return bytes;
    },
    close() {},
  };
}
