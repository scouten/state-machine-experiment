import test from "node:test";
import assert from "node:assert/strict";
import { assertRuntimeRuns, runtimeObservations, type RuntimeRun } from "../scripts/runtime-record.ts";

test("upstream runtime matrix requires all browser/path combinations and every exact selected case", () => {
  const ids = ["reader-a", "reader-b"];
  const runs: RuntimeRun[] = (["inline", "worker"] as const).flatMap((runtime) =>
    ["chromium", "firefox", "webkit"].map((browser) => ({
      runtime, browser, exit: 0, outcomes: ids.map((id) => ({ id, status: "passed" as const })),
    })));
  assert.doesNotThrow(() => assertRuntimeRuns(runs, ids));
  assert.deepEqual(runtimeObservations(runs, ids), ids.map((id) => ({ id, status: "passed" })));
  for (const mutate of [
    (r: RuntimeRun[]) => { r.pop() },
    (r: RuntimeRun[]) => { r[3].runtime = "inline" },
    (r: RuntimeRun[]) => { r[1].browser = "chromium" },
    (r: RuntimeRun[]) => { r[2].outcomes.pop() },
    (r: RuntimeRun[]) => { r[4].outcomes[1].id = ids[0] },
    (r: RuntimeRun[]) => { r[5].outcomes[0].id = "unknown" },
    (r: RuntimeRun[]) => { r[0].exit = -1 },
  ]) {
    const changed = structuredClone(runs);
    mutate(changed);
    assert.throws(() => assertRuntimeRuns(changed, ids));
  }
  assert.throws(() => assertRuntimeRuns(runs, []));
  assert.throws(() => assertRuntimeRuns(runs, ["reader-a", "reader-a"]));
  const skipped = runs.map((run, index) => index === 0 ? {
    ...run, outcomes: [{ id: ids[0], status: "skipped" }, run.outcomes[1]],
  } : run);
  assert.throws(() => assertRuntimeRuns(skipped, ids));
  const failed = structuredClone(runs);
  failed[5].exit = 1;
  failed[5].outcomes[0].status = "failed";
  assert.doesNotThrow(() => assertRuntimeRuns(failed, ids));
  assert.equal(failed.every((run) => run.exit === 0 && run.outcomes.every((outcome) => outcome.status === "passed")), false);
  assert.deepEqual(runtimeObservations(failed, ids), ids.map((id) => ({ id, status: "failed" })));
  failed[5].exit = 0;
  assert.deepEqual(runtimeObservations(failed, ids), [
    { id: "reader-a", status: "failed" }, { id: "reader-b", status: "passed" },
  ]);
});
