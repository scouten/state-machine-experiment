import type { Settings } from "@contentauth/c2pa-utilities";
import type { Config, Signer } from "./index.ts";
import type { HttpHostOptions } from "./http.ts";

export const protocol = "c2pa-state-machine-worker-v1";
export type NetworkOptions = Omit<HttpHostOptions, "signal">;
export type SignerInfo = Pick<Signer, "alg" | "certs" | "timeAuthorityUrl"> & { timestamp: boolean };
export type Command =
  | { method: "init"; source: Config["wasmSrc"] }
  | { method: "read"; format?: string; blob: Blob; settings?: Settings;
      detached?: Uint8Array; remote?: NetworkOptions; ocsp?: NetworkOptions }
  | { method: "builder"; definition: Record<string, unknown> }
  | { method: "readerMethod"; handle: number; name: "activeLabel" | "activeManifest" | "manifestStore" | "json" }
  | { method: "sign"; handle: number; signer: SignerInfo; format?: string; blob: Blob }
  | { method: "free"; handle: number };
export interface Failure { name: string; message: string }
export type Outcome = { ok: true; value: unknown } | { ok: false; error: Failure };
export type HostMessage =
  | { protocol: typeof protocol; kind: "command"; id: number; command: Command }
  | { protocol: typeof protocol; kind: "callbackResult"; id: number; outcome: Outcome }
  | { protocol: typeof protocol; kind: "abort"; id: number; channel: "remote" | "ocsp"; error: Failure };
export type WorkerMessage =
  | { protocol: typeof protocol; kind: "ready" }
  | { protocol: typeof protocol; kind: "result"; id: number; outcome: Outcome }
  | { protocol: typeof protocol; kind: "callback"; id: number; operation: number;
      method: "sign" | "timestamp"; bytes: Uint8Array; url?: string };

export function failure(cause: unknown): Failure {
  return cause instanceof Error
    ? { name: cause.name, message: cause.message }
    : { name: "Error", message: String(cause) };
}
export function restore(value: Failure): Error {
  const error = new Error(value.message);
  error.name = value.name;
  return error;
}
