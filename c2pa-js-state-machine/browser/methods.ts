import { test as baseTest } from "vitest";
import wasmSrc from "@contentauth/c2pa-web/resources/c2pa.wasm?url";
import { factory } from "./backend.ts";

export const test = baseTest.extend<{ c2pa: Awaited<ReturnType<typeof factory.createC2pa>> }>({
  c2pa: async ({}, use) => {
    const client = await factory.createC2pa({ wasmSrc });
    try {
      await use(client);
    } finally {
      client.dispose();
    }
  },
});
export { describe, expect } from "vitest";
