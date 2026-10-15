import { boundedHttpHost, type HttpHostOptions } from "./http.ts";

export type RemoteManifestOptions = HttpHostOptions;

export function remoteManifestHost(options: RemoteManifestOptions): (url: string) => Promise<Uint8Array> {
  return boundedHttpHost(options, "Remote manifest");
}
