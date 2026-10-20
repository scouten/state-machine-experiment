import corpus from "./fixtures/corpus.json" with { type: "json" };

export function hasTimestampPolicyDifference(item: typeof corpus[number]): boolean {
  return item.name === "legacy-v1-timestamp/disabled";
}

/** Explicitly different expected policy, not a claim of legacy report equality. */
export function expectedReport(item: typeof corpus[number]) {
  if (!hasTimestampPolicyDifference(item)) return item.manifestStore;
  const report = item.manifestStore;
  if (!report) throw new Error("Timestamp policy case requires a signed baseline");
  const active = report.validation_results.activeManifest;
  const timestamp = active.success.find((status) => status.code === "timeStamp.trusted");
  if (!timestamp) throw new Error("Legacy timestamp baseline must contain the known trust difference");
  return {
    ...report,
    validation_results: {
      ...report.validation_results,
      activeManifest: {
        ...active,
        success: active.success.filter((status) => status !== timestamp),
        informational: [...active.informational, {
          code: "timeStamp.untrusted",
          explanation: "timestamp cert untrusted: DigiCert Timestamp 2023",
          url: timestamp.url,
        }],
      },
    },
  };
}
