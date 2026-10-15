import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createC2pa, Context, Reader, type Runtime } from "c2pa-js-state-machine/inline";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import legacyAssetSrc from "test/assets/C_with_CAWG_data.jpg?url";
import legacyRoot from "test/trust/anchor-correct.pem?raw";
import legacyIdentityRoot from "test/trust/anchor-cawg.pem?raw";

const runtimes: Runtime[] = [];
async function runtime() {
  const instance = await createC2pa({ wasmSrc });
  runtimes.push(instance);
  return instance;
}

describe("M2 reader reporting and Context", () => {
  beforeEach(() => { vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-01T00:00:00Z")) });
  afterEach(() => {
    for (const instance of runtimes.splice(0)) {
      instance.dispose();
      expect(instance.liveResources).toBe(0);
    }
    vi.restoreAllMocks();
  });

  test("decodes assertion values and applies separate CAWG trust settings", async () => {
    const client = await runtime();
    const asset = await (await fetch(legacyAssetSrc)).blob();
    const context = new Context({
      trust: { trustAnchors: legacyRoot },
      cawgTrust: { trustAnchors: legacyIdentityRoot },
      verify: { verifyTrust: true, ocspFetch: false },
    });
    const reader = await Reader.fromBlob(client, "image/jpeg", asset, context);
    expect(reader).not.toBeNull();

    const report = await reader!.manifestStore();
    const active = report.manifests[report.active_manifest!] as {
      assertions: { label: string; created?: boolean; data?: unknown }[];
    };
    const actions = active.assertions.find((assertion) => assertion.label === "c2pa.actions.v2");
    expect(actions).toEqual({
      label: "c2pa.actions.v2",
      created: true,
      data: {
        actions: [{
          action: "c2pa.created",
          digitalSourceType: " http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
        }],
        allActionsIncluded: true,
      },
    });
    const identity = active.assertions.find((assertion) => assertion.label === "cawg.identity");
    const identityData = identity?.data as {
      signer_payload?: { referenced_assertions?: { hash: unknown }[] };
    } | undefined;
    expect(Array.isArray(identityData?.signer_payload?.referenced_assertions?.[0]?.hash)).toBe(true);
    expect(report.validation_results.activeManifest.success.some((status) => status.code === "cawg.x509.credential.trusted")).toBe(true);
    expect(report.validation_results.specVersion).toBe("2.4.0");
    expect(report.validation_results.activeManifest.success.some(
      (status) => status.code === "claimSignature.validated",
    )).toBe(true);
  });

  test("rejects verification settings that reader cannot honor", async () => {
    const client = await runtime();
    const context = new Context({ verify: { remoteManifestFetch: true } });
    await expect(Reader.fromBlob(client, "image/jpeg", new Blob([]), context))
      .rejects.toThrow(/Unsupported reader setting: verify.remoteManifestFetch/);
  });
});
