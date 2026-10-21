// Run only via chunks.mjs: loads addons compiled in the disposable baseline mirror.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign, X509Certificate } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [mirror, output, variant, sampleCount] = process.argv.slice(2);
const load = (path) => import(pathToFileURL(resolve(mirror, path)).href);
const { adapter } = await load("js/src/node/adapter.mjs");
const { read, build } = await load("js/src/shared/drive.mjs");
const { createClient } = await load("js/src/node/client.mjs");
const cert = readFileSync(resolve(mirror, "contentauth-c2pa-builder/tests/fixtures/test-signer.der"));
const key = createPrivateKey(readFileSync(resolve(mirror, "contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem")));
const settings = {
  trust: { anchors: [{ trust_kind: "manifest", trust_anchors: new X509Certificate(cert).toString() }] },
  verify: { ocsp_fetch: false },
};
const now = 1800000000;
const definition = {
  title: "chunk-experiment.jpg",
  instance_id: "xmp:iid:00000000-0000-4000-8000-000000000001",
  label: "urn:uuid:00000000-0000-4000-8000-000000000002",
  claim_generator_info: [{ name: "chunk-experiment", version: "1" }],
  assertions: [{ label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } }],
};
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const referencePath = resolve(output, "reference.json");
const reference = variant === "baseline" ? {} : JSON.parse(readFileSync(referencePath));

// Count asset-path, source-visible allocations/copies only. No allocator/RSS claim.
// The real shared drive and native adapter execute unchanged.
function instrument() {
  const counts = { advanceCalls: 0, fulfillCalls: 0, byteReplies: 0,
    replyBytes: 0, maxReplyBytes: 0, writeBuffers: 0, writeBytes: 0,
    growthAllocations: 0, growthAllocatedBytes: 0, growthCopyBytes: 0 };
  let capacity = 0;
  const wrap = (session) => ({
    advance() {
      counts.advanceCalls++;
      const step = session.advance();
      for (const request of step.requests ?? []) {
        if (request.kind !== "write") continue;
        counts.writeBuffers++;
        counts.writeBytes += request.bytes.length;
        const end = request.offset + request.bytes.length;
        if (end > capacity) {
          const next = Math.max(end, capacity * 2, 4096);
          counts.growthAllocations++;
          counts.growthAllocatedBytes += next;
          counts.growthCopyBytes += capacity;
          capacity = next;
        }
      }
      return step;
    },
    fulfill(id, kind, value) {
      counts.fulfillCalls++;
      if (kind === "bytes") {
        counts.byteReplies++;
        counts.replyBytes += value.length;
        counts.maxReplyBytes = Math.max(counts.maxReplyBytes, value.length);
      }
      return session.fulfill(id, kind, value);
    },
    finish: () => session.finish(), close: () => session.close(),
  });
  return { counts, adapter: {
    create: (...args) => wrap(adapter.create(...args)),
    createBuild: (...args) => wrap(adapter.createBuild(...args)),
  } };
}
function accounting(counts, operation, outputBytes) {
  const building = operation === "build";
  return { ...counts,
    // Reader Buffer.from(arrayBuffer, offset, length) is a view; builder
    // Buffer.from(Uint8Array) copies. Both Neon fulfill functions call to_vec.
    assetCopyBytes: counts.replyBytes * (building ? 2 : 1) +
      counts.writeBytes * 2 + counts.growthCopyBytes + (building ? outputBytes : 0),
    assetAllocationEvents: counts.byteReplies * (building ? 2 : 1) +
      counts.writeBuffers + counts.growthAllocations + (building ? 2 : 0),
  };
}
const results = [];
const client = createClient();
try {
  for (const [name, size] of [["tiny", 4], ["large", 64 * 1024 * 1024 + 17]]) {
    const source = new Uint8Array(size);
    source.set([255, 216, 255, 217]);
    let signature;
    let signingInput;
    if (reference[name]) {
      signature = Buffer.from(reference[name].signature, "hex");
      signingInput = reference[name].signingInput;
    }
    const signer = async ({ data }) => {
      if (signature) assert.equal(digest(data), signingInput, "signing input changed");
      else {
        signingInput = digest(data);
        signature = sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
      }
      return signature;
    };
    const signed = await build(adapter, source, JSON.stringify(definition), [cert], signer);
    const verified = await read(adapter, signed.asset, JSON.stringify(settings), now);
    assert.equal(verified.report.validation_state, "Trusted");
    const proof = { signature: signature.toString("hex"), signingInput,
      assetSha256: digest(signed.asset), manifestSha256: digest(signed.manifest),
      outputBytes: signed.asset.length, exclusions: signed.exclusions, report: verified.report };
    if (reference[name]) assert.deepEqual(proof, reference[name], "C2PA bytes/report changed");
    else reference[name] = proof;
    // Exercise the actual Worker protocol outside timing as an end-to-end gate.
    const workerSigned = await client.sign(source, definition, {
      alg: "es256", certs: [cert], sign: (data) => signer({ data }),
    });
    assert.equal(digest(workerSigned.asset), proof.assetSha256);
    assert.deepEqual((await client.read(workerSigned.asset, { settings, now })).report, proof.report);
    for (const operation of ["read", "build"]) {
      let expected;
      const elapsedMs = [];
      for (let iteration = -1; iteration < Number(sampleCount); iteration++) {
        const measured = instrument();
        const started = performance.now();
        const result = operation === "read"
          ? await read(measured.adapter, signed.asset, JSON.stringify(settings), now)
          : await build(measured.adapter, source, JSON.stringify(definition), [cert], signer);
        const elapsed = performance.now() - started;
        // Hashes, equality, validation gates and fixture construction aren't timed.
        if (operation === "read") assert.deepEqual(result.report, proof.report);
        else {
          assert.equal(digest(result.asset), proof.assetSha256);
          assert.equal(digest(result.manifest), proof.manifestSha256);
          assert.deepEqual(result.exclusions, proof.exclusions);
        }
        assert.equal(measured.counts.replyBytes, result.stats.bytes);
        assert.equal(measured.counts.byteReplies, result.stats.reads);
        if (operation === "build") {
          assert.equal(measured.counts.writeBytes, result.stats.writtenBytes);
          assert.equal(measured.counts.writeBuffers, result.stats.writes);
        }
        const counters = accounting(measured.counts, operation, signed.asset.length);
        expected ??= { counters, stats: result.stats };
        assert.deepEqual({ counters, stats: result.stats }, expected);
        if (iteration >= 0) elapsedMs.push(elapsed);
      }
      results.push({ name, sourceBytes: size, outputBytes: signed.asset.length, operation,
        elapsedMs, medianMs: [...elapsedMs].sort((a, b) => a - b)[Math.floor(elapsedMs.length / 2)],
        ...expected });
    }
  }
} finally { await client.dispose() }
if (variant === "baseline") writeFileSync(referencePath, JSON.stringify(reference, null, 2) + "\n");
console.log(JSON.stringify({ proof: Object.fromEntries(Object.entries(reference).map(([name, value]) =>
  [name, { assetSha256: value.assetSha256, manifestSha256: value.manifestSha256,
    validationState: value.report.validation_state }])), measurements: results }));
