import { assertFreshEvidence, type EvidenceFingerprint } from "./contract.ts";

export function assertPackageRecord(value: unknown, expected: EvidenceFingerprint): asserts value is EvidenceFingerprint & {
  schema: 1; reports: { browser: string; ok: true; paths: string[] }[];
} {
  if (value === null || typeof value !== "object") throw new Error("Missing package evidence");
  const record = value as Record<string, unknown>;
  if (record.schema !== 1 || record.bundler !== "vite-6.3.6" ||
      typeof record.archiveSha256 !== "string" || !/^[a-f0-9]{64}$/.test(record.archiveSha256) ||
      !Array.isArray(record.reports) || record.reports.length !== 3)
    throw new Error("Invalid package evidence");
  assertFreshEvidence({
    inventorySha256: String(record.inventorySha256), lockSha256: String(record.lockSha256),
    harnessSha256: String(record.harnessSha256), artifactsSha256: String(record.artifactsSha256),
  }, expected);
  for (const [index, report] of record.reports.entries()) {
    if (!report || report.browser !== ["chromium", "firefox", "webkit"][index] || report.ok !== true ||
        JSON.stringify(report.paths) !== JSON.stringify(["inline-url", "worker-url", "inline-module", "worker-module"]))
      throw new Error("Incomplete packed-consumer browser proof");
  }
  const files = record.files;
  if (!Array.isArray(files) || files.length === 0 ||
      files.some((file) => typeof file !== "string" || (file !== "package.json" && !/^dist\/[^/]+$/.test(file))) ||
      ["package.json", "dist/index.js", "dist/index.d.ts", "dist/worker.js", "dist/worker.d.ts",
        "dist/worker-entry.js", "dist/worker-entry.d.ts", "dist/state_machine.js", "dist/state_machine_bg.wasm"]
        .some((file) => !files.includes(file)))
    throw new Error("Invalid packed-consumer file inventory");
}
