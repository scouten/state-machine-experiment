import type { Observation } from "./contract.ts";

export interface RuntimeRun {
  browser: string;
  runtime: "inline" | "worker";
  exit: number | null;
  outcomes: Observation[];
}

export function assertRuntimeRuns(value: unknown, selectedIds: string[]): asserts value is RuntimeRun[] {
  if (selectedIds.length === 0 || new Set(selectedIds).size !== selectedIds.length)
    throw new Error("Runtime proof requires a nonempty unique upstream selection");
  if (!Array.isArray(value) || value.length !== 6)
    throw new Error("Runtime proof requires inline and Worker on all three browsers");
  const expected = ["inline", "worker"].flatMap((runtime) =>
    ["chromium", "firefox", "webkit"].map((browser) => `${runtime}:${browser}`));
  for (const [index, run] of value.entries()) {
    if (run === null || typeof run !== "object" ||
        `${run.runtime}:${run.browser}` !== expected[index] ||
        (run.exit !== null && (!Number.isInteger(run.exit) || run.exit < 0)) ||
        !Array.isArray(run.outcomes) || run.outcomes.length !== selectedIds.length)
      throw new Error("Missing, duplicate or invalid runtime/browser evidence");
    const ids = new Set<string>();
    for (const outcome of run.outcomes) {
      if (!outcome || !selectedIds.includes(outcome.id) || ids.has(outcome.id) ||
          !["passed", "failed"].includes(outcome.status))
        throw new Error("Missing, duplicate, skipped or unexpected upstream runtime outcome");
      ids.add(outcome.id);
    }

  }
}

export function runtimeObservations(runs: RuntimeRun[], selectedIds: string[]): Observation[] {
  assertRuntimeRuns(runs, selectedIds);
  return selectedIds.map((id) => ({
    id, status: runs.every((run) => run.exit === 0 &&
      run.outcomes.find((outcome) => outcome.id === id)?.status === "passed") ? "passed" : "failed",
  }));
}
