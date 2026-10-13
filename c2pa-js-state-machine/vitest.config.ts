import { defineConfig } from "vitest/config";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { root, upstreamRoot } from "./scripts/contract.ts";

const web = join(upstreamRoot, "packages/c2pa-web");
const state = process.env.CONTRACT_BACKEND === "state-machine";
const browser = process.env.CONTRACT_BROWSER ?? "chromium";
if (!["chromium", "firefox", "webkit"].includes(browser)) throw new Error(`Unknown browser: ${browser}`);
const trustFixtures = ["correct", "cawg", "incorrect"].map((name) => `test/trust/anchor-${name}.pem`);
export default defineConfig({
  define: { __CONTRACT_BACKEND__: JSON.stringify(process.env.CONTRACT_BACKEND ?? "legacy") },
  plugins: [{
    name: "pinned-oracle-imports",
    enforce: "pre",
    resolveId(id, importer) {
      if (id === "@contentauth/c2pa-utilities" && importer?.startsWith(web))
        return fileURLToPath(import.meta.resolve(state ? "@contentauth/c2pa-utilities" : "@contentauth/c2pa-web"));
      if (trustFixtures.some((file) => id === `${file}?raw`))
        return `\0oracle-trust:${id.slice(0, -4)}`;
      if (id === "@contentauth/c2pa-web/resources/c2pa.wasm?url")
        return (state && importer?.endsWith("/browser/methods.ts")
          ? join(root, ".cache/generated/state_machine_bg.wasm")
          : fileURLToPath(import.meta.resolve("@contentauth/c2pa-web/resources/c2pa.wasm"))) + "?url";
      if (id === "test/methods.js") return join(root, "browser/methods.ts");
      if (id.startsWith("test/")) return join(web, id.replace(/\.js$/, ".ts"));
      if (importer?.endsWith("/src/lib/reader.spec.ts") && id === "./reader.js")
        return join(root, "browser/backend.ts");
      if (importer?.endsWith("/src/lib/reader.spec.ts") && id === "./c2pa.js")
        return join(root, "browser/create.ts");
    },
    load(id) {
      if (id.startsWith("\0oracle-trust:")) {
        const file = id.slice("\0oracle-trust:".length);
        if (!trustFixtures.includes(file)) throw new Error("Unknown public trust fixture");
        return `export default ${JSON.stringify(readFileSync(join(web, file), "utf8"))};`;
      }
    },
  }],
  assetsInclude: ["**/*.jpg", "**/*.mp4", "**/*.m4s"],
  optimizeDeps: { exclude: ["@contentauth/c2pa-web", "@contentauth/c2pa-utilities"] },
  server: { fs: { allow: [root] } },
  test: {
    include: [".cache/upstream/packages/c2pa-web/src/lib/reader.spec.ts", ...(state ? ["browser/m1.spec.ts"] : [])],
    exclude: [],
    browser: {
      enabled: true,
      headless: true,
      screenshotFailures: false,
      provider: "playwright",
      instances: [{ browser: browser as "chromium" | "firefox" | "webkit" }],
    },
  },
});
