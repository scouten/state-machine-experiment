import { createC2pa as legacyCreateC2pa, Reader as LegacyReader } from "@contentauth/c2pa-web";

export const MAX_SIZE_IN_BYTES = 10 ** 9;
const legacy = { createC2pa: legacyCreateC2pa, Reader: LegacyReader };

export async function backend(name: string) {
  if (name === "legacy") return legacy;
  if (name === "state-machine") {
    const { createC2pa, Reader } = await import("c2pa-js-state-machine/inline");
    return { createC2pa, Reader };
  }
  throw new Error(`Unknown contract backend: ${name}`);
}

export const factory = await backend(__CONTRACT_BACKEND__);
export const Reader = factory.Reader;
export const createC2pa = factory.createC2pa;
