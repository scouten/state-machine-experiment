import { boundedHttpHost, type HttpHostOptions } from "./http.ts";

/** OCSP may use explicitly authorized HTTP origins: signed DER authenticates the response. */
export type OcspOptions = HttpHostOptions;

export function ocspHost(options: OcspOptions): (url: string, request: Uint8Array) => Promise<Uint8Array> {
  return boundedHttpHost(options, "OCSP", true);
}
