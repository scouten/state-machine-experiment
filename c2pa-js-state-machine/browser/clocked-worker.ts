Date.now = () => Date.parse("2026-09-01T00:00:00Z");
await import("../src/worker-entry.ts");
