import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  optimizeDeps: { exclude: ["@contentauth/c2pa-web", "@contentauth/c2pa-utilities"] },
  server: { fs: { allow: [fileURLToPath(new URL("..", import.meta.url))] } },
  test: {
    include: ["browser/**/*.spec.ts"],
    browser: {
      enabled: true,
      headless: true,
      screenshotFailures: false,
      provider: "playwright",
      instances: [{ browser: "chromium" }, { browser: "firefox" }, { browser: "webkit" }],
    },
  },
});
