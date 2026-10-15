import test from "node:test";
import assert from "node:assert/strict";
import { contextJson, factoryContext, readerDefaults, rejectBuilderDefaults } from "../src/settings.ts";
import { Context } from "@contentauth/c2pa-utilities";

test("reader factory defaults are isolated snapshots and overrides reuse legacy deep merging", () => {
  const input = { trust: { trustAnchors: ["anchor"] }, verify: { verifyTrust: true, ocspFetch: false } };
  const defaults = readerDefaults(input);
  input.trust.trustAnchors[0] = "mutated";
  const override = { trust: { trustAnchors: [] as string[] } };
  const context = factoryContext(defaults, override);
  assert.deepEqual(context.settings, { trust: { trustAnchors: ["anchor"] }, verify: input.verify });
  override.trust.trustAnchors.push("later");
  assert.deepEqual(context.settings?.trust?.trustAnchors, ["anchor"]);
  assert.deepEqual(defaults.trust?.trustAnchors, ["anchor"]);
  assert.throws(() => rejectBuilderDefaults(defaults), /Builder factory settings/);
  assert.doesNotThrow(() => rejectBuilderDefaults({}));
});

test("settings reject unsupported input and require an operation host for online OCSP", async () => {
  for (const settings of [null, [], { verify: { verifyTrust: "false" } },
    { trust: { verifyTrustList: "false" } }, { cawgTrust: { verifyTrustList: 0 } },
    { verify: { remoteManifestFetch: true } }, { trust: { trustAnchors: [4] } }, { builder: {} }])
    assert.throws(() => readerDefaults(settings));
  const defaults = readerDefaults({ verify: { ocspFetch: true } });
  await assert.rejects(contextJson(factoryContext(defaults, undefined)), /Unsupported reader setting/);
  assert.doesNotThrow(() => readerDefaults({ cawgTrust: { userAnchors: [] } }));
  assert.equal(await contextJson(undefined), undefined);
  await assert.doesNotReject(contextJson(new Context({ verify: { ocspFetch: true } }), true));
});

test("trust verdict and trust-list switches preserve pinned wire semantics", async () => {
  const settings = { trust: { trustAnchors: "ignored", verifyTrustList: false },
    cawgTrust: { trustAnchors: "ignored identity", verifyTrustList: false },
    verify: { verifyTrust: false } };
  const json = await contextJson(factoryContext(readerDefaults(settings), undefined));
  assert.equal(JSON.parse(json!).verify.verify_trust, false);
  assert.equal(JSON.parse(json!).trust, undefined);
  const enabled = factoryContext(readerDefaults(settings), { verify: { verifyTrust: true } });
  assert.equal(JSON.parse((await contextJson(enabled))!).verify.verify_trust, true);
  assert.equal(JSON.parse((await contextJson(enabled))!).trust, undefined);
});
