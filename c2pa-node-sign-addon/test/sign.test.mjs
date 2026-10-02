import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey, sign as cryptoSign, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import test, { after, before } from "node:test";

import { Builder, signAsset } from "../index.mjs";

// The read-back uses the *existing* reader addon. Its native module is a
// build product (`index.node`, git-ignored): build it here if it is
// missing, so `npm test` works from a clean checkout. CI's job builds it
// explicitly first.
const READER_DIR = new URL("../../c2pa-node-compat-addon/", import.meta.url).pathname;
if (!existsSync(join(READER_DIR, "index.node"))) {
  execFileSync("npm", ["run", "build"], { cwd: READER_DIR, stdio: "inherit" });
}
const { Reader } = await import(join(READER_DIR, "index.mjs"));

const fixture = (p) => new URL(`../../${p}`, import.meta.url).pathname;
const SOURCE = fixture("contentauth-c2pa-reader/tests/fixtures/C.jpg");
const CERT_DER = readFileSync(fixture("contentauth-c2pa-builder/tests/fixtures/test-signer.der"));
const KEY = createPrivateKey(readFileSync(fixture("contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem")));

// The baseline case (contentauth-c2pa-sign-baseline's BASELINE_DEFINITION).
const BASELINE = {
  title: "baseline.jpg",
  instance_id: "xmp:iid:00000000-0000-4000-8000-000000000001",
  label: "urn:uuid:00000000-0000-4000-8000-000000000002",
  claim_generator_info: [{ name: "c2pa-sign-baseline", version: "0.1" }],
  assertions: [
    {
      label: "c2pa.actions.v2",
      data: {
        actions: [
          {
            action: "c2pa.created",
            digitalSourceType: "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
          },
        ],
      },
    },
  ],
};

/** A signer holding the test key in-process; COSE wants raw r || s. */
function testSigner(delayMs = 0, stats = { calls: 0 }) {
  return {
    stats,
    alg: "es256",
    certs: [CERT_DER],
    async sign(data) {
      stats.calls++;
      if (delayMs) await sleep(delayMs);
      return cryptoSign("sha256", data, { key: KEY, dsaEncoding: "ieee-p1363" });
    },
  };
}

const trustSettings = {
  trust: {
    anchors: [{ trust_anchors: new X509Certificate(CERT_DER).toString(), trust_kind: "manifest" }],
  },
  verify: { ocsp_fetch: false },
};

let dir;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "c2pa-sign-test-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

function assertBaseline(reader) {
  const json = reader.json();
  assert.equal(json.validation_state, "Trusted");
  assert.equal(reader.activeLabel(), BASELINE.label);
  const active = reader.getActive();
  assert.equal(active.title, "baseline.jpg");
  assert.equal(active.instance_id, BASELINE.instance_id);
  const labels = active.assertions;
  assert.ok(labels.includes("c2pa.actions.v2"), JSON.stringify(labels));
  assert.ok(labels.includes("c2pa.hash.data"), JSON.stringify(labels));
}

test("the baseline case signs a JPEG file that reads back Trusted", async () => {
  const output = join(dir, "signed.jpg");
  const signer = testSigner();
  const result = await signAsset({ path: SOURCE }, BASELINE, signer, { output: { path: output } });

  assert.equal(signer.stats.calls, 1);
  assert.ok(result.manifest.length > 0);
  assert.ok(result.manifestLen >= result.manifest.length);
  assert.equal(result.buffer, undefined);

  // The reported range holds the manifest store's bytes within its framing.
  const signed = readFileSync(output);
  assert.ok(signed.includes(result.manifest.subarray(0, 64)));
  assert.ok(result.manifestStart + result.manifestLen <= signed.length);

  assertBaseline(await Reader.fromAsset({ path: output }, trustSettings));
  // Without the anchor, the same asset is valid but not Trusted.
  const untrusted = await Reader.fromAsset({ path: output }, { verify: { ocsp_fetch: false } });
  assert.notEqual(untrusted.json().validation_state, "Trusted");
});

test("with no output path the signed asset is returned, identical to the file route", async () => {
  const output = join(dir, "same.jpg");
  const options = { output: { path: output } };
  const viaFile = await new Builder(JSON.stringify(BASELINE)).sign({ path: SOURCE }, testSigner(), options);
  const viaBuffer = await signAsset({ path: SOURCE }, BASELINE, testSigner());

  assert.ok(Buffer.isBuffer(viaBuffer.buffer));
  assert.equal(viaBuffer.manifestStart, viaFile.manifestStart);
  assert.equal(viaBuffer.buffer.length, readFileSync(output).length);
  assert.ok(viaBuffer.buffer.subarray(0, 2).equals(Buffer.from([0xff, 0xd8])));

  const path = join(dir, "from-buffer.jpg");
  writeFileSync(path, viaBuffer.buffer);
  assertBaseline(await Reader.fromAsset({ path }, trustSettings));
});

test("a signer that rejects rejects the promise and leaves nothing behind", async () => {
  const sub = mkdtempSync(join(dir, "reject-"));
  const output = join(sub, "out.jpg");
  const signer = {
    ...testSigner(),
    async sign() {
      throw new Error("hsm unavailable");
    },
  };
  await assert.rejects(
    signAsset({ path: SOURCE }, BASELINE, signer, { output: { path: output } }),
    { message: "hsm unavailable" },
  );
  assert.deepEqual(readdirSync(sub), [], "no output and no temp file");
});

test("a failed build leaves an existing output untouched", async () => {
  const output = join(dir, "precious.jpg");
  writeFileSync(output, "precious");
  const signer = { ...testSigner(), sign: async () => { throw new Error("no"); } };
  await assert.rejects(signAsset({ path: SOURCE }, BASELINE, signer, { output: { path: output } }));
  assert.equal(readFileSync(output, "utf8"), "precious");
});

test("a successful build replaces an existing output and leaves no temp file", async () => {
  const sub = mkdtempSync(join(dir, "replace-"));
  const output = join(sub, "out.jpg");
  writeFileSync(output, "old");
  await signAsset({ path: SOURCE }, BASELINE, testSigner(), { output: { path: output } });
  assert.deepEqual(readdirSync(sub), ["out.jpg"]);
  assertBaseline(await Reader.fromAsset({ path: output }, trustSettings));
});

test("a slow async signer does not block the event loop", async () => {
  let ticks = 0;
  const timer = setInterval(() => ticks++, 5);
  try {
    const started = Date.now();
    await signAsset({ path: SOURCE }, BASELINE, testSigner(300));
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 300, `${elapsed} ms`);
    // A 5 ms timer over a 300 ms signature: if the loop were blocked
    // while signing there would be (almost) none.
    assert.ok(ticks >= 20, `only ${ticks} ticks in ${elapsed} ms`);
  } finally {
    clearInterval(timer);
  }
});

test("two signings interleave on one thread while their signers wait", async () => {
  const started = Date.now();
  const [a, b] = await Promise.all([
    signAsset({ path: SOURCE }, BASELINE, testSigner(300)),
    signAsset({ path: SOURCE }, BASELINE, testSigner(300)),
  ]);
  const elapsed = Date.now() - started;
  assert.deepEqual(a.manifest.length, b.manifest.length);
  assert.ok(elapsed < 550, `${elapsed} ms: signatures did not overlap`);
});

test("the host's concurrency limit changes how requests are issued, not the result", async () => {
  const unlimited = await signAsset({ path: SOURCE }, BASELINE, testSigner());
  const serial = await signAsset({ path: SOURCE }, BASELINE, testSigner(), { concurrency: 1 });
  const two = await signAsset({ path: SOURCE }, BASELINE, testSigner(), { concurrency: 2 });
  // ECDSA is randomized, so signatures differ; everything else is identical.
  for (const other of [serial, two]) {
    assert.equal(other.buffer.length, unlimited.buffer.length);
    assert.equal(other.manifestStart, unlimited.manifestStart);
    assert.equal(other.manifestLen, unlimited.manifestLen);
  }
});

test("definition and argument errors reject with the Rust error string as the name", async () => {
  await assert.rejects(signAsset({ path: SOURCE }, "{", testSigner()), (err) =>
    err.name.startsWith("Definition(BadDefinition("),
  );
  await assert.rejects(
    signAsset({ path: SOURCE }, { ...BASELINE, claim_generator_info: [] }, testSigner()),
    (err) => err.name.startsWith("Definition("),
  );
  await assert.rejects(signAsset({ path: SOURCE }, BASELINE, testSigner(), { format: "image/png" }), {
    name: "C2pa(UnsupportedType)",
  });
  await assert.rejects(
    signAsset({ path: SOURCE }, BASELINE, { ...testSigner(), alg: "rot13" }),
    (err) => err.name.startsWith("C2pa(BadParam("),
  );
  await assert.rejects(signAsset({ path: "/no/such/file.jpg" }, BASELINE, testSigner()), {
    code: "ENOENT",
  });
  await assert.rejects(signAsset({}, BASELINE, testSigner()), TypeError);
});

test("a signer for the wrong algorithm, or returning junk, fails the build", async () => {
  const sub = mkdtempSync(join(dir, "wrong-"));
  const output = join(sub, "out.jpg");
  await assert.rejects(
    signAsset({ path: SOURCE }, BASELINE, { ...testSigner(), alg: "es256", sign: async () => "nope" }, {
      output: { path: output },
    }),
    TypeError,
  );
  assert.deepEqual(readdirSync(sub), []);
});
