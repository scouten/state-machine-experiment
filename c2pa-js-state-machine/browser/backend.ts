import { createC2pa as legacyCreateC2pa, Reader as LegacyReader } from "@contentauth/c2pa-web";
import workerSrc from "./clocked-worker.ts?worker&url";
import type { Config } from "c2pa-js-state-machine/inline";

export const MAX_SIZE_IN_BYTES = 10 ** 9;
const legacy = { createC2pa: legacyCreateC2pa, Reader: LegacyReader };

export async function backend(name: string, runtime = "inline") {
  if (name === "legacy") return legacy;
  if (name === "state-machine") {
    if (runtime === "worker") {
      const { createC2pa, Reader } = await import("c2pa-js-state-machine/worker");
      return { Reader, createC2pa: (config: Config) =>
        createC2pa({ ...config, workerSrc: new URL(workerSrc, location.href) }) };
    }
    if (runtime !== "inline") throw new Error(`Unknown contract runtime: ${runtime}`);
    const { createC2pa, Reader } = await import("c2pa-js-state-machine/inline");
    return { createC2pa, Reader };
  }
  throw new Error(`Unknown contract backend: ${name}`);
}

export const factory = await backend(__CONTRACT_BACKEND__, __CONTRACT_RUNTIME__);
export const Reader = factory.Reader;
export const createC2pa = factory.createC2pa;
