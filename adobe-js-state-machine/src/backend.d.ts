declare module "c2pa-node-compat-addon" {
  import type { Manifest, ManifestStore } from "@contentauth/c2pa-types";

  export class Reader {
    static fromAsset(
      asset: { path: string; mimeType?: string } | { buffer: Buffer; mimeType: string },
      settings: {
        verify: { verify_trust: boolean; ocsp_fetch: boolean };
        trust?: { trust_anchors?: string; user_anchors?: string; verify_trust_list?: boolean };
        cawg_trust?: { trust_anchors?: string; user_anchors?: string; verify_trust_list?: boolean };
      },
    ): Promise<Reader | null>;
    json(): ManifestStore;
    activeLabel(): string | undefined;
    getActive(): Manifest | undefined;
    remoteUrl(): string;
    isEmbedded(): boolean;
    resourceToAsset(
      uri: string,
      asset: { buffer: Buffer | null } | { path: string },
    ): Promise<{ buffer: Buffer; bytes_written: number }>;
  }
}
