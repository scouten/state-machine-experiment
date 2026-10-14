import type { ManifestProjection } from "./index.ts";

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function status(value: unknown): value is { code: string; url?: string; explanation?: string } {
  return object(value) && typeof value.code === "string" &&
    (value.url === undefined || typeof value.url === "string") &&
    (value.explanation === undefined || typeof value.explanation === "string");
}
function statuses(value: unknown): boolean { return Array.isArray(value) && value.every(status) }
export function isProjection(value: unknown): value is ManifestProjection {
  if (!object(value) || !object(value.manifests) ||
      !(value.validation_state === "Trusted" || value.validation_state === "Valid" ||
        value.validation_state === "Invalid") ||
      (value.active_manifest !== undefined && typeof value.active_manifest !== "string") ||
      (value.validation_status !== undefined && !statuses(value.validation_status))) return false;
  const results = value.validation_results;
  if (!object(results) || typeof results.specVersion !== "string") return false;
  const activeManifest = results.activeManifest;
  return object(activeManifest) && ["success", "informational", "failure"].every((bucket) =>
    statuses(activeManifest[bucket]));
}
