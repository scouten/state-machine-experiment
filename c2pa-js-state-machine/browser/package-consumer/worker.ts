Date.now = () => Date.parse("2026-09-01T00:00:00Z");
await import("c2pa-js-state-machine/worker-entry");
export {};
