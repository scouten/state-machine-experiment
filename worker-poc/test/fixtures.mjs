import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign, X509Certificate } from "node:crypto";
import { mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { Builder } from "../../c2pa-node-sign-addon/index.mjs";
import { Reader } from "../../c2pa-node-compat-addon/index.mjs";
import { createClient } from "../node/client.mjs";

const directory = new URL("../generated/", import.meta.url);
await mkdir(directory, { recursive: true });
const cert = await readFile(new URL("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der", import.meta.url));
const key = createPrivateKey(await readFile(new URL("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem", import.meta.url)));
const now = 1_800_000_000;
const settings = {
  trust: { anchors: [{ trust_kind: "manifest", trust_anchors: new X509Certificate(cert).toString() }] },
  verify: { ocsp_fetch: false },
};
const definition = {
  title: "shared-worker-proof.jpg",
  instance_id: "xmp:iid:00000000-0000-4000-8000-000000000001",
  label: "urn:uuid:00000000-0000-4000-8000-000000000002",
  claim_generator_info: [{ name: "shared-worker-proof", version: "1" }],
  assertions: [{ label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } }],
};
const signer = { alg: "es256", certs: [cert], async sign(data) {
  return sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
} };
const files = {};
const client = createClient();
try {
  for (const [name, length] of [["small", 4], ["large", 64 * 1024 * 1024]]) {
    const source = Buffer.alloc(length);
    source.set([0xff, 0xd8, 0xff, 0xd9]);
    const input = new URL(`${name}-source.jpg`, directory);
    await writeFile(input, source);
    let result;
    try { result = await new Builder(definition).sign({ path: input.pathname }, signer) }
    finally { await unlink(input) }
    await writeFile(new URL(`${name}.jpg`, directory), result.buffer);
    const reader = await Reader.fromAsset({ buffer: result.buffer }, settings, { now: () => now * 1000 });
    const expected = reader.json();
    assert.equal(expected.validation_state, "Trusted");
    for (const code of ["claimSignature.validated", "signingCredential.trusted", "assertion.dataHash.match"]) {
      assert.ok(expected.validation_status.some((status) => status.code === code), code);
    }
    const worker = await client.read(result.buffer, { settings, now });
    assert.deepEqual(worker.report, expected);
    files[name] = { bytes: result.buffer.length,
      sha256: createHash("sha256").update(result.buffer).digest("hex"),
      report: expected, stats: worker.stats };
  }
  await writeFile(new URL("fixtures.json", directory), JSON.stringify({ now, settings, files }, null, 2));
} finally { await client.dispose() }
console.log("Generated small/64 MiB signed fixtures; direct Neon host and Worker reports agree.");
