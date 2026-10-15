import * as inline from "c2pa-js-state-machine/inline";
import * as worker from "c2pa-js-state-machine/worker";
import wasmSrc from "c2pa-js-state-machine/resources/state-machine.wasm?url";
import workerSrc from "./worker.ts?worker&url";
import directWorkerSrc from "c2pa-js-state-machine/worker-entry?worker&url";

const bytes = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
async function run() {
  Date.now = () => Date.parse("2026-09-01T00:00:00Z");
  const response = await fetch("/fixtures.json");
  check(response.ok, "Missing consumer test fixtures");
  const fixtures = await response.json() as {
    source: string; cert: string; key: string; definition: Record<string, unknown>;
  };
  const sourceBytes = bytes(fixtures.source);
  const source = new Blob([sourceBytes], { type: "image/jpeg" });
  const root = `-----BEGIN CERTIFICATE-----\n${fixtures.cert.match(/.{1,64}/g)?.join("\n")}\n-----END CERTIFICATE-----\n`;
  const settings = { trust: { trustAnchors: root }, verify: { verifyTrust: true, ocspFetch: false } };
  const key = await crypto.subtle.importKey("pkcs8", bytes(fixtures.key.replace(/-----[^-]+-----|\s/g, "")),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  check(!key.extractable, "Signing key must stay caller-owned");
  const signer: inline.Signer = {
    alg: "es256", certs: [bytes(fixtures.cert)],
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(data)));
    },
  };
  const module = await WebAssembly.compile(await (await fetch(wasmSrc)).arrayBuffer());
  const mode = new URL(location.href).searchParams.get("mode") === "module" ? "module" : "url";
  const wasm = mode === "module" ? module : wasmSrc;
  const inlineClient = await inline.createC2pa({ wasmSrc: wasm, settings });
  const workerClient = await worker.createC2pa({ wasmSrc: wasm, workerSrc: new URL(workerSrc, location.href), settings });
  const clients = [inlineClient, workerClient];
  const results: string[] = [];
  const resourceAsset = new Blob([await (await fetch("/C_with_CAWG_data.jpg")).arrayBuffer()], { type: "image/jpeg" });
  const thumbnailBytes = new Uint8Array(await (await fetch("/C_with_CAWG_data_thumbnail.jpg")).arrayBuffer());
  const iconAsset = new Blob([await (await fetch("/generator-icons-v2.jpg")).arrayBuffer()], { type: "image/jpeg" });
  const iconBytes = new Uint8Array(await (await fetch("/generator-icon.svg")).arrayBuffer());
  const ingredientAsset = new Blob([await (await fetch("/ingredient-thumbnails-v2.jpg")).arrayBuffer()], { type: "image/jpeg" });
  const dataAsset = new Blob([await (await fetch("/ingredient-data-v2.jpg")).arrayBuffer()], { type: "image/jpeg" });
  const dataBytes = new Uint8Array(await (await fetch("/ingredient-data.json")).arrayBuffer());
  try {
    const direct = await worker.createC2pa({ wasmSrc: wasm, workerSrc: new URL(directWorkerSrc, location.href) });
    try {
      check(await direct.reader.fromBlob("image/jpeg", new Blob([Uint8Array.of(0xff, 0xd8, 0xff, 0xd9)])) === null,
        "Direct packaged Worker entry did not read unsigned JPEG");
      check(direct.liveResources === 0, "Direct Worker leaked a reader");
    } finally { direct.dispose() }
    for (const [index, client] of clients.entries()) {
      check(Array.isArray(fixtures.definition.assertions), "Missing fixture assertions");
      const definition = { ...fixtures.definition, assertions: [...fixtures.definition.assertions, {
        label: "c2pa.ingredient.v3", created: false, data: {
          "dc:title": "Installed input", relationship: "componentOf",
          digitalSourceType: "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
          metadata: { dateTime: "2026-10-14T10:20:30Z", reviewRatings: [{
            explanation: "Installed review", code: "ingredient.modified", value: 5,
          }] },
        },
      }] };
      // Runtime facades share the implemented reader/builder method shapes.
      const builder = index === 0
        ? await inline.Builder.fromDefinition(inlineClient, definition)
        : await worker.Builder.fromDefinition(workerClient, definition);
      const result = await builder.sign(signer, "image/jpeg", source);
      await builder.free();
      for (const target of clients) {
        const reader = await target.reader.fromBlob("image/jpeg",
          new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" }));
        check(reader, "Signed output must have a reader");
        const report = await reader.json();
        check(report.validation_state === "Trusted", JSON.stringify(report));
        const active: unknown = await reader.activeManifest();
        check(active && typeof active === "object" && "ingredients" in active &&
          Array.isArray(active.ingredients) && active.ingredients.length === 1,
          "Installed ingredient metadata missing");
        const ingredient: unknown = active.ingredients[0];
        check(ingredient && typeof ingredient === "object" && "title" in ingredient &&
          ingredient.title === "Installed input" && "relationship" in ingredient &&
          ingredient.relationship === "componentOf", "Installed ingredient metadata differs");
        check("metadata" in ingredient &&
          JSON.stringify(ingredient.metadata) === JSON.stringify(definition.assertions.at(-1)?.data.metadata),
          "Installed ingredient assertion reviews differ");
        await reader.free();
        const iconReader = await client.reader.fromBlob("image/jpeg", iconAsset);
        check(iconReader, "Installed generator icon asset must read");
        const iconStore = await iconReader.manifestStore();
        check(iconStore.validation_state === "Trusted", "Installed generator icon asset is not trusted");
        const iconManifest = iconStore.manifests[iconStore.active_manifest!];
        check(iconManifest && typeof iconManifest === "object" && "claim_generator_info" in iconManifest &&
          Array.isArray(iconManifest.claim_generator_info), "Installed generators are missing");
        const generator: unknown = iconManifest.claim_generator_info[0];
        check(generator && typeof generator === "object" && "icon" in generator &&
          generator.icon && typeof generator.icon === "object" && "identifier" in generator.icon &&
          typeof generator.icon.identifier === "string" && "format" in generator.icon &&
          generator.icon.format === "image/svg+xml", "Installed generator icon reference is missing");
        const icon = generator.icon;
        const identifier = icon.identifier;
        check(typeof identifier === "string", "Installed icon identifier is invalid");
        const firstIcon = await iconReader.resourceToBytes(identifier);
        check(firstIcon.length === iconBytes.length && firstIcon.every((byte, i) => byte === iconBytes[i]),
          "Installed generator icon bytes differ");
        firstIcon.fill(0);
        const secondIcon = await iconReader.resourceToBytes(identifier);
        check(secondIcon.every((byte, i) => byte === iconBytes[i]), "Installed icon bytes are not independent");
        await iconReader.free();
        const ingredientReader = await target.reader.fromBlob("image/jpeg", ingredientAsset);
        check(ingredientReader, "Installed ingredient thumbnail asset must read");
        const ingredientStore = await ingredientReader.manifestStore();
        check(ingredientStore.validation_state === "Trusted", "Installed ingredient thumbnail asset is not trusted");
        const ingredientManifest = ingredientStore.manifests[ingredientStore.active_manifest!];
        check(ingredientManifest && typeof ingredientManifest === "object" && "ingredients" in ingredientManifest &&
          Array.isArray(ingredientManifest.ingredients) && ingredientManifest.ingredients.length === 2,
          "Installed ingredient thumbnails are missing");
        const identifiers = new Set<string>();
        for (const ingredient of ingredientManifest.ingredients) {
          check(ingredient && typeof ingredient === "object" && "thumbnail" in ingredient &&
            ingredient.thumbnail && typeof ingredient.thumbnail === "object" &&
            "identifier" in ingredient.thumbnail && typeof ingredient.thumbnail.identifier === "string" &&
            "format" in ingredient.thumbnail && ingredient.thumbnail.format === "image/svg+xml",
            "Installed ingredient thumbnail reference differs");
          const identifier = ingredient.thumbnail.identifier;
          identifiers.add(identifier);
          const first = await ingredientReader.resourceToBytes(identifier);
          check(first.length === iconBytes.length && first.every((byte, i) => byte === iconBytes[i]),
            "Installed ingredient thumbnail bytes differ");
          first.fill(0);
          const second = await ingredientReader.resourceToBytes(identifier);
          check(second.length === iconBytes.length && second.every((byte, i) => byte === iconBytes[i]),
            "Installed ingredient thumbnail copies are not independent");
        }
        check(identifiers.size === 2 && [...identifiers].some((id) => id.endsWith("c2pa.thumbnail.ingredient__1")),
          "Installed ingredient thumbnails lost positional resource IDs");
        check(JSON.stringify(await ingredientReader.activeManifest()) === JSON.stringify(ingredientManifest),
          "Installed ingredient thumbnail reporting surfaces disagree");
        await ingredientReader.free();
        const dataReader = await target.reader.fromBlob("image/jpeg", dataAsset);
        check(dataReader, "Installed ingredient data asset must read");
        const dataStore = await dataReader.manifestStore();
        check(dataStore.validation_state === "Trusted", "Installed ingredient data asset is not trusted");
        const dataManifest = dataStore.manifests[dataStore.active_manifest!];
        check(dataManifest && typeof dataManifest === "object" && "ingredients" in dataManifest &&
          Array.isArray(dataManifest.ingredients) && dataManifest.ingredients.length === 2,
          "Installed ingredient data is missing");
        const dataIds = new Set<string>();
        for (const ingredient of dataManifest.ingredients) {
          check(ingredient && typeof ingredient === "object" && "data" in ingredient &&
            ingredient.data && typeof ingredient.data === "object" &&
            "identifier" in ingredient.data && typeof ingredient.data.identifier === "string" &&
            "format" in ingredient.data && ingredient.data.format === "application/json",
            "Installed ingredient data reference differs");
          const identifier = ingredient.data.identifier;
          dataIds.add(identifier);
          const first = await dataReader.resourceToBytes(identifier);
          check(first.length === dataBytes.length && first.every((byte, i) => byte === dataBytes[i]),
            "Installed ingredient data bytes differ");
          first.fill(0);
          const second = await dataReader.resourceToBytes(identifier);
          check(second.length === dataBytes.length && second.every((byte, i) => byte === dataBytes[i]),
            "Installed ingredient data copies are not independent");
        }
        check(dataIds.size === 2 && [...dataIds].some((id) => id.endsWith("c2pa.embedded-data__1")),
          "Installed ingredient data lost positional resource IDs");
        const withThumbnail: unknown = dataManifest.ingredients[0];
        check(withThumbnail && typeof withThumbnail === "object" && "thumbnail" in withThumbnail &&
          withThumbnail.thumbnail && typeof withThumbnail.thumbnail === "object" &&
          "identifier" in withThumbnail.thumbnail && typeof withThumbnail.thumbnail.identifier === "string",
          "Installed ingredient data hid its thumbnail");
        const combinedThumbnail = await dataReader.resourceToBytes(withThumbnail.thumbnail.identifier);
        check(combinedThumbnail.length === iconBytes.length && combinedThumbnail.every((byte, i) => byte === iconBytes[i]),
          "Installed combined ingredient thumbnail bytes differ");
        check(JSON.stringify(await dataReader.activeManifest()) === JSON.stringify(dataManifest),
          "Installed ingredient data reporting surfaces disagree");
        await dataReader.free();
        const unchecked = await target.reader.fromBlob("image/jpeg",
          new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" }),
          { verify: { verifyTrust: false } });
        check(unchecked, "Disabled-trust installed reader missing");
        const uncheckedReport = await unchecked.manifestStore();
        check(uncheckedReport.validation_state === "Valid" &&
          uncheckedReport.validation_results.activeManifest.success.some((status) => status.code === "claimSignature.validated") &&
          !uncheckedReport.validation_results.activeManifest.success.some((status) => status.code === "signingCredential.trusted"),
          "Installed disabled claim trust must retain signature validation without a trusted verdict");
        await unchecked.free();
        const signed = new Blob([new Uint8Array(result.asset)], { type: "image/jpeg" });
        const read = (context: inline.Context) => target === inlineClient
          ? inline.Reader.fromBlob(inlineClient, undefined, signed, context)
          : worker.Reader.fromBlob(workerClient, undefined, signed, context);
        const options = structuredClone(settings);
        const context = new inline.Context(options);
        const firstResolution = context.toJson();
        const isolated = new inline.Context({ verify: { verifyTrust: false, ocspFetch: false } });
        const concurrent = await Promise.all([read(context), read(isolated), read(context)]);
        for (const [index, reader] of concurrent.entries()) {
          check(reader, "Concurrent installed reader missing");
          check((await reader.manifestStore()).validation_state === (index === 1 ? "Valid" : "Trusted"),
            "Installed concurrent Contexts leaked trust policy");
          await reader.free();
        }
        options.verify.verifyTrust = false;
        options.trust.trustAnchors = "";
        const cached = await read(context);
        check(cached && (await cached.manifestStore()).validation_state === "Trusted",
          "Installed Worker re-resolved cached Context settings");
        check(context.toJson() === firstResolution, "Installed Context resolution is not memoized");
        await cached.free();
      }
      const detachedBuilder = index === 0
        ? await inline.Builder.fromDefinition(inlineClient, fixtures.definition)
        : await worker.Builder.fromDefinition(workerClient, fixtures.definition);
      const detached = await detachedBuilder.signDetached(signer, source);
      await detachedBuilder.free();
      check(detached.asset.length === source.size, "Detached asset length changed");
      check(detached.asset.every((value, offset) => value === sourceBytes[offset]), "Detached bytes changed");
      const reader = await client.reader.fromBlob("image/jpeg", source, settings, detached.manifest);
      check(reader, "Detached store must read");
      check((await reader.json()).validation_state === "Trusted", "Detached output untrusted");
      await reader.free();
      const resourceReader = await client.reader.fromBlob("image/jpeg", resourceAsset);
      check(resourceReader, "Embedded resource asset must read");
      const active: unknown = await resourceReader.activeManifest();
      check(active && typeof active === "object" && "thumbnail" in active, "Missing installed thumbnail metadata");
      check("signature_info" in active && active.signature_info &&
        typeof active.signature_info === "object" && "cert_serial_number" in active.signature_info &&
        active.signature_info.cert_serial_number === "640229841392226413189608867977836244731148734950",
        "Installed claim signer metadata differs");
      const store = await resourceReader.manifestStore();
      const json = await resourceReader.json();
      check(store.validation_state === "Valid" &&
        store.validation_status?.map((status) => status.code).join(",") ===
          "signingCredential.untrusted,cawg.x509.credential.untrusted",
        "Installed failure-only trust summary differs");
      const validation = (results: typeof store.validation_results) =>
        (["success", "informational", "failure"] as const).map((bucket) =>
          results.activeManifest[bucket].map((status) => [status.code, status.url, status.explanation]));
      check(json.validation_state === store.validation_state &&
        JSON.stringify(validation(json.validation_results)) === JSON.stringify(validation(store.validation_results)),
        "Installed JSON and manifest-store validation reports disagree");
      check(store.validation_results.activeManifest.success.some(
        (status) => status.code === "claimSignature.validated"),
        "Installed signature success missing from validation results");
      check(JSON.stringify(store.manifests[store.active_manifest!]) === JSON.stringify(active),
        "Installed active-manifest reporting surfaces disagree");
      const identity = (manifest: unknown): unknown => {
        check(manifest && typeof manifest === "object" && "assertions" in manifest &&
          Array.isArray(manifest.assertions), "Missing manifest assertions");
        const assertion: unknown = manifest.assertions.find((item: unknown) =>
          item && typeof item === "object" && "label" in item && item.label === "cawg.identity");
        check(assertion && typeof assertion === "object" && "data" in assertion, "Missing identity assertion");
        return assertion.data;
      };
      const objectIdentity = identity(store.manifests[store.active_manifest!]);
      const jsonIdentity = identity(json.manifests[store.active_manifest!]);
      const firstHash = (data: unknown): unknown => {
        check(data && typeof data === "object" && "signer_payload" in data, "Missing identity payload");
        const payload = data.signer_payload;
        check(payload && typeof payload === "object" && "referenced_assertions" in payload &&
          Array.isArray(payload.referenced_assertions), "Missing identity references");
        const ref: unknown = payload.referenced_assertions[0];
        check(ref && typeof ref === "object" && "hash" in ref, "Missing identity hash");
        return ref.hash;
      };
      const arrayHash = firstHash(objectIdentity);
      check(Array.isArray(arrayHash) && arrayHash.every((byte: unknown) =>
        typeof byte === "number" && Number.isInteger(byte) && byte >= 0 && byte <= 255),
        "Object identity hash must retain bytes");
      check(firstHash(jsonIdentity) === btoa(String.fromCharCode(...arrayHash)),
        "JSON identity hash must use padded standard base64");
      const ref = active.thumbnail;
      check(ref && typeof ref === "object" && "identifier" in ref && typeof ref.identifier === "string",
        "Invalid installed thumbnail reference");
      const resource = await resourceReader.resourceToBytes(ref.identifier);
      check(resource.length === thumbnailBytes.length &&
        resource.every((value, offset) => value === thumbnailBytes[offset]), "Installed thumbnail bytes differ");
      resource.fill(0);
      const again = await resourceReader.resourceToBytes(ref.identifier);
      check(again.every((value, offset) => value === thumbnailBytes[offset]), "Installed resource aliasing");
      await resourceReader.free();
      let rejected = false;
      try { await client.reader.fromBlob("image/jpeg", new Blob([Uint8Array.of(1, 2)]), settings) }
      catch { rejected = true }
      check(rejected, "Malformed asset unexpectedly accepted");
      check(client.liveResources === 0, "Resource leak");
      results.push(`${index === 0 ? "inline" : "worker"}-${mode}`);
    }
  } finally { for (const client of clients) client.dispose() }
  return results;
}
run().then((paths) => {
  document.body.dataset.result = JSON.stringify({ ok: true, paths });
}, (cause: unknown) => {
  document.body.dataset.result = JSON.stringify({ ok: false, error: cause instanceof Error ? cause.message : String(cause) });
});
