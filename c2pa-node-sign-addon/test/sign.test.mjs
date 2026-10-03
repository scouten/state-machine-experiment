import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { createPrivateKey, sign as cryptoSign, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import test, { after, before } from "node:test";

import { _native as native, answerRequest, Builder, openOutput, openSource, signAsset } from "../index.mjs";

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

test("a signer whose algorithm differs from the session's is refused before signing", async () => {
  const stats = { calls: 0 };
  const signer = testSigner(0, stats);
  // The session is built for the signer's algorithm, so ask the request
  // handler directly for a signature in another one.
  await assert.rejects(
    answerRequest({ kind: "sign", alg: "ps256", data: Buffer.from("x") }, { signer }),
    /signer is es256, the session asked for ps256/,
  );
  assert.equal(stats.calls, 0);
});

test("an unknown request kind is an error rather than silently ignored", async () => {
  await assert.rejects(answerRequest({ kind: "mystery" }, {}), /unsupported request mystery/);
});

test("the native session rejects misuse with errors rather than crashing", () => {
  const session = native.buildNew(JSON.stringify(BASELINE), "image/jpeg", "es256", [CERT_DER]);

  const step = native.buildAdvance(session);
  assert.equal(step.done, false);
  assert.ok(step.requests.length > 0);

  assert.throws(() => native.buildFulfill(session, step.requests[0].id, "nonsense", 0), /unknown reply kind/);
  assert.throws(() => native.buildFulfill(session, 999999, "length", 0), Error);
  // Finishing before the build completes is an error, and consumes the session.
  assert.throws(() => native.buildFinish(session), Error);

  assert.throws(() => native.buildAdvance(session), /already finished/);
  assert.throws(() => native.buildFulfill(session, 0, "written"), /already finished/);
  assert.throws(() => native.buildFinish(session), /already finished/);
});

test("a source reports a read past its end, and a tiny or unknown file is an unsupported type", async () => {
  const tiny = join(dir, "tiny.dat");
  writeFileSync(tiny, Buffer.from([1, 2]));

  const source = await openSource({ path: tiny });
  try {
    assert.equal(await source.size(), 2);
    await assert.rejects(source.read(0, 10), /unexpected end of file/);
  } finally {
    await source.close();
  }

  // Neither sniffable (too short) nor a known extension.
  await assert.rejects(signAsset({ path: tiny }, BASELINE, testSigner()), /UnsupportedType/);

  const text = join(dir, "text.dat");
  writeFileSync(text, "not a jpeg at all");
  await assert.rejects(signAsset({ path: text }, BASELINE, testSigner()), /UnsupportedType/);
  await assert.rejects(openSource({}), TypeError);
});

test("a signer without certificates is rejected rather than signing an unverifiable asset", async () => {
  const { certs, ...noCerts } = testSigner();
  await assert.rejects(signAsset({ path: SOURCE }, BASELINE, noCerts));
});

test("a file output answers reads, length and writes, commits by rename, and discards cleanly", async () => {
  const sub = mkdtempSync(join(dir, "out-"));
  const dest = join(sub, "out.bin");

  const out = await openOutput({ path: dest });
  await out.target.write(0, Buffer.from("hello"));
  await out.target.write(5, Buffer.from(" world"));
  assert.equal(await out.target.size(), 11);
  assert.equal((await out.target.read(6, 5)).toString(), "world");
  await assert.rejects(out.target.read(8, 10), /unexpected end of output/);
  await out.commit();
  assert.equal(readFileSync(dest).toString(), "hello world");
  assert.deepEqual(readdirSync(sub), ["out.bin"]);

  const discarded = await openOutput({ path: join(sub, "never.bin") });
  await discarded.target.write(0, Buffer.from("x"));
  await discarded.discard();
  assert.deepEqual(readdirSync(sub), ["out.bin"]);
});

test("an in-memory output grows past its capacity, zero-fills gaps and returns exactly what was written", async () => {
  const out = await openOutput({});
  await out.target.write(0, Buffer.from([1, 2, 3]));
  await out.target.write(10, Buffer.from([9]));
  await out.target.write(1, Buffer.from([7]));
  assert.equal(await out.target.size(), 11);
  assert.deepEqual([...(await out.target.read(0, 4))], [1, 7, 3, 0]);
  // A read past the end is clipped to what was written, not stale capacity.
  assert.deepEqual([...(await out.target.read(9, 10))], [0, 9]);
  assert.deepEqual([...(await out.commit())], [1, 7, 3, 0, 0, 0, 0, 0, 0, 0, 9]);
  await out.discard();
});

// ---------------------------------------------------------------------------
// Timestamps. The "authority" is a local HTTP server returning a canned
// TimeStampResp whose token is an opaque stand-in: the session embeds it
// without decoding it, and whether a real token is trusted is the
// reader's business, covered by its own suite.

const TOKEN = Buffer.alloc(300, 0x42);

/** A DER TimeStampResp: `status`, then (if granted) a token whose content is TOKEN. */
function tsResponse(status = 0) {
  const token = status === 0 ? Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x2c]), TOKEN]) : Buffer.alloc(0);
  const body = Buffer.concat([Buffer.from([0x30, 0x03, 0x02, 0x01, status]), token]);
  const header = Buffer.from([0x30, 0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([header, body]);
}

/** Starts a fake authority; `seen` collects what it was POSTed. */
async function fakeAuthority(respond) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      seen.push({ method: req.method, type: req.headers["content-type"], body: Buffer.concat(chunks) });
      const [code, body] = respond();
      res.writeHead(code, { "Content-Type": "application/timestamp-reply" });
      res.end(body);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    seen,
    url: `http://127.0.0.1:${server.address().port}/tsa`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test("a tsa_url timestamps the claim: Node POSTs the request and the token lands in the manifest", async () => {
  const authority = await fakeAuthority(() => [200, tsResponse(0)]);
  try {
    const output = join(dir, "timestamped.jpg");
    const result = await signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: authority.url }, testSigner(), {
      output: { path: output },
    });

    assert.equal(authority.seen.length, 1);
    assert.equal(authority.seen[0].method, "POST");
    assert.equal(authority.seen[0].type, "application/timestamp-query");
    // A DER TimeStampReq (SEQUENCE) with certReq set.
    assert.equal(authority.seen[0].body[0], 0x30);
    assert.deepEqual([...authority.seen[0].body.subarray(-3)], [0x01, 0x01, 0xff]);

    assert.ok(result.manifest.includes(TOKEN), "the token must be in the manifest store");
    // The signed asset still reads back, signature and hard binding intact.
    const reader = await Reader.fromAsset({ path: output }, trustSettings);
    assert.ok(reader.getActive().assertions.includes("c2pa.hash.data"));
  } finally {
    await authority.close();
  }
});

test("a signer's timeAuthorityUrl and sendTimestampRequest replace the definition and fetch", async () => {
  const sent = [];
  const signer = {
    ...testSigner(),
    timeAuthorityUrl: "https://tsa.example/from-signer",
    async sendTimestampRequest(url, request) {
      sent.push({ url, request });
      return tsResponse(0);
    },
  };
  const result = await signAsset({ path: SOURCE }, BASELINE, signer);

  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, "https://tsa.example/from-signer");
  assert.ok(Buffer.isBuffer(sent[0].request));
  assert.ok(result.manifest.includes(TOKEN));

  // The definition's own tsa_url wins over the signer's.
  sent.length = 0;
  await signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: "https://tsa.example/from-definition" }, signer);
  assert.equal(sent[0].url, "https://tsa.example/from-definition");
});

test("a refusing, failing or malformed authority fails the build and leaves nothing behind", async () => {
  const cases = [
    [() => [200, tsResponse(2)], /refused/],
    [() => [503, "busy"], /answered 503/],
    [() => [200, Buffer.from([1, 2, 3])], /malformed|TimeStampResp/],
  ];
  for (const [respond, expected] of cases) {
    const authority = await fakeAuthority(respond);
    try {
      const sub = mkdtempSync(join(dir, "ts-fail-"));
      await assert.rejects(
        signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: authority.url }, testSigner(), {
          output: { path: join(sub, "out.jpg") },
        }),
        expected,
      );
      assert.deepEqual(readdirSync(sub), []);
    } finally {
      await authority.close();
    }
  }
});

test("an unreachable authority fails the build rather than going untimestamped", async () => {
  const authority = await fakeAuthority(() => [200, tsResponse(0)]);
  const { url } = authority;
  await authority.close();
  await assert.rejects(signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: url }, testSigner()));
});

test("a tsa_url that is not http(s) is rejected as a bad definition", async () => {
  await assert.rejects(
    signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: "file:///etc/passwd" }, testSigner()),
    (error) => error.name.startsWith("Definition(BadDefinition("),
  );
});

test("a signer whose sendTimestampRequest returns junk is a type error", async () => {
  const signer = { ...testSigner(), timeAuthorityUrl: "https://tsa.example/", sendTimestampRequest: async () => "nope" };
  await assert.rejects(signAsset({ path: SOURCE }, BASELINE, signer), TypeError);
});

test("a definition that is not JSON still reports Rust's error when the signer names an authority", async () => {
  const signer = { ...testSigner(), timeAuthorityUrl: "https://tsa.example/" };
  await assert.rejects(
    signAsset({ path: SOURCE }, "{ not json", signer),
    (error) => error.name.startsWith("Definition(BadDefinition("),
  );
});

test("an implausibly large timestamp response fails the build", async () => {
  const authority = await fakeAuthority(() => [200, Buffer.alloc(1024 * 1024 + 1, 0x30)]);
  try {
    await assert.rejects(
      signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: authority.url }, testSigner()),
      /implausibly large/,
    );
  } finally {
    await authority.close();
  }
});

test("a chunked timestamp response with no declared length is abandoned once it passes the limit", async () => {
  let sent = 0;
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(200); // no Content-Length: chunked
      const chunk = Buffer.alloc(256 * 1024, 0x30);
      const timer = setInterval(() => {
        if (res.destroyed) return clearInterval(timer);
        sent += chunk.length;
        res.write(chunk);
      }, 1);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await assert.rejects(
      signAsset({ path: SOURCE }, { ...BASELINE, tsa_url: `http://127.0.0.1:${server.address().port}/` }, testSigner()),
      /implausibly large/,
    );
    // It stopped reading shortly after the 1 MiB limit rather than draining a long stream.
    await sleep(50);
    const afterAbort = sent;
    await sleep(50);
    assert.equal(sent, afterAbort, "the server should have seen the connection close");
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
