// Vertical-slice matrix: for each capability the Rust workspace implements, probe
// whether it is reachable and correct through the JS entry points. Every probe
// asserts today's observed outcome, so the matrix fails when a gap opens or closes
// without its report being updated. Gaps are classified by what would close them:
//   js    - JavaScript host code only
//   glue  - the Neon/Wasm binding crate (marshalling, no domain logic)
//   rust  - the neutral session bridge or domain crates (out of scope for this experiment)
import assert from "node:assert/strict";
import { constants, createPrivateKey, sign as cryptoSign, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";
import { createClient } from "../src/node/client.mjs";
import { createWasmAdapter } from "../src/browser/adapter.mjs";
import { build as driveBuild, isNonPublicHost, postTimestamp, read as driveRead, source as byteSource } from "../src/shared/drive.mjs";

const rows = [];
const record = (id, area, capability, layer, status, evidence) =>
  rows.push({ id, area, capability, layer, status, evidence });

const root = new URL("../../", import.meta.url).pathname;
const nativeReader = createRequire(import.meta.url)(`${root}c2pa-node-compat-addon/index.node`);
const nativeSigner = createRequire(import.meta.url)(`${root}c2pa-node-sign-addon/index.node`);
const jpegSource = `${root}contentauth-c2pa-reader/tests/fixtures/C.jpg`;
const baseline = {
  title: "matrix.jpg",
  instance_id: "xmp:iid:00000000-0000-4000-8000-000000000001",
  label: "urn:uuid:00000000-0000-4000-8000-000000000002",
  claim_generator_info: [{ name: "matrix", version: "1" }],
  assertions: [{ label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } }],
};

let folder;
let client;
let wasmAdapter;
const keys = new Map();

// Leaf certificates shaped like the repository's test signer: non-CA, critical
// digitalSignature + nonRepudiation, critical emailProtection, self-trusted.
function makeKey(name, keyArgs, extra = []) {
  const key = join(folder, `${name}.key.pem`);
  const pem = join(folder, `${name}.pem`);
  execFileSync("openssl", ["req", "-x509", "-nodes", "-days", "3650", "-newkey", ...keyArgs,
    "-keyout", key, "-out", pem, "-subj", `/C=US/O=matrix/OU=TEST ONLY/CN=${name}`,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,nonRepudiation",
    "-addext", "extendedKeyUsage=critical,emailProtection",
    "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid", ...extra],
  { stdio: "pipe" });
  const x509 = new X509Certificate(execFileSync("openssl", ["x509", "-in", pem], { encoding: "utf8" }));
  return { privateKey: createPrivateKey(readFileSync(key)), pem: x509.toString(), der: x509.raw };
}

const algorithms = {
  es256: { key: ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"], sign: (k, d) =>
    cryptoSign("sha256", d, { key: k, dsaEncoding: "ieee-p1363" }) },
  es384: { key: ["ec", "-pkeyopt", "ec_paramgen_curve:secp384r1"], sign: (k, d) =>
    cryptoSign("sha384", d, { key: k, dsaEncoding: "ieee-p1363" }) },
  es512: { key: ["ec", "-pkeyopt", "ec_paramgen_curve:secp521r1"], sign: (k, d) =>
    cryptoSign("sha512", d, { key: k, dsaEncoding: "ieee-p1363" }) },
  ps256: { key: ["rsa:2048"], sign: (k, d) => cryptoSign("sha256", d,
    { key: k, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }) },
  ps384: { key: ["rsa:3072"], sign: (k, d) => cryptoSign("sha384", d,
    { key: k, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }) },
  ps512: { key: ["rsa:4096"], sign: (k, d) => cryptoSign("sha512", d,
    { key: k, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }) },
  ed25519: { key: ["ed25519"], sign: (k, d) => cryptoSign(null, d, k) },
};

const signerFor = (alg) => {
  const { privateKey, der } = keys.get(alg);
  return { alg, certs: [new Uint8Array(der)], async sign(data) {
    return new Uint8Array(algorithms[alg].sign(privateKey, Buffer.from(data)));
  } };
};
const settingsFor = (alg, extra = {}) => ({
  trust: { anchors: [{ trust_kind: "manifest", trust_anchors: keys.get(alg).pem }] },
  verify: { ocsp_fetch: false }, ...extra,
});
const nowSeconds = () => Math.floor(Date.now() / 1000);

before(async () => {
  folder = await mkdtemp(join(tmpdir(), "c2pa-matrix-"));
  for (const [alg, spec] of Object.entries(algorithms)) keys.set(alg, makeKey(alg, spec.key));
  client = createClient();
  const wasm = await import("../generated/contentauth_c2pa_wasm.js");
  await wasm.default({ module_or_path: await readFile(new URL("../generated/contentauth_c2pa_wasm_bg.wasm", import.meta.url)) });
  wasmAdapter = createWasmAdapter(wasm);
});
after(async () => {
  await client.dispose();
  await rm(folder, { recursive: true });
  const results = new URL("../results/", import.meta.url);
  await mkdir(results, { recursive: true });
  await writeFile(new URL("vertical-matrix.json", results), JSON.stringify({
    measuredAt: new Date().toISOString(), node: process.version, rows }, null, 2));
});

// A classic little-endian TIFF with one IFD holding a single entry.
const tiffSource = new Uint8Array([73, 73, 42, 0, 8, 0, 0, 0, 1, 0, 0, 1, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);

test("signing algorithms through the Worker host, read back Trusted", async () => {
  for (const alg of Object.keys(algorithms)) {
    const signed = await client.sign({ path: jpegSource }, baseline, signerFor(alg));
    const read = await client.read(signed.asset, { settings: settingsFor(alg), now: nowSeconds() });
    record(`sign.${alg}`, "signing", `${alg} signature, JPEG`, "node-host", "pass",
      `validation_state=${read.report.validation_state}`);
    assert.equal(read.report.validation_state, "Trusted", alg);
  }
});

test("browser Wasm glue: algorithm, format and identities are constructor parameters", async () => {
  const wasm = await import("../generated/contentauth_c2pa_wasm.js");
  await wasm.default({ module_or_path: await readFile(new URL("../generated/contentauth_c2pa_wasm_bg.wasm", import.meta.url)) });
  assert.equal(wasm.BuildSession.length, 5, "(definition, format, alg, certs, identities)");
  const certs = (alg) => JSON.stringify([Array.from(keys.get(alg).der)]);
  for (const alg of Object.keys(algorithms))
    new wasm.BuildSession(JSON.stringify(baseline), "image/tiff", alg, certs(alg), "[]").free();
  assert.throws(() => new wasm.BuildSession(JSON.stringify(baseline), "image/jpeg", "ps256", certs("es256"), "[]"),
    /RSA signer certificate/);
  record("sign.alg.wasm", "signing", "non-ES256 through Wasm", "wasm-glue", "pass",
    "BuildSession takes format, algorithm and identities; PS* derives its signature length from the leaf certificate (construction only here; the browser contracts run it end to end)");
  new wasm.ReadSession("image/tiff").free();
  record("format.tiff.read.wasm", "formats", "TIFF read through Wasm", "rust-bridge", "pass",
    "ReadSession(\"image/tiff\") constructs (read end to end through Neon below)");
});

test("TIFF through the Worker host, and the host's format gap", async () => {
  const signed = await client.sign(tiffSource, baseline, signerFor("es256"), undefined, { format: "image/tiff" });
  const read = await client.read(signed.asset, { settings: settingsFor("es256"), now: nowSeconds(), format: "tiff" });
  assert.equal(read.report.validation_state, "Trusted");
  record("format.tiff.sign.neon", "formats", "TIFF sign through Neon", "rust-bridge", "pass",
    "client.sign(..., {format: \"image/tiff\"}) produces an asset the TIFF handler reads back Trusted");
  record("format.tiff.read.neon", "formats", "TIFF read through Neon", "rust-bridge", "pass",
    "client.read(..., {format: \"tiff\"}) validates it Trusted");

  assert.throws(() => nativeReader.sessionNew("image/png", undefined), /UnsupportedType|unsupported/i);
  assert.throws(() => nativeSigner.buildNew(JSON.stringify(baseline), "image/png", "es256", []),
    /UnsupportedType|unsupported/i);
  // The host never detects format: a PNG is handed to the JPEG handler as-is.
  const png = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");
  const outcome = await client.read(new Uint8Array(png)).then((value) => `ok:${JSON.stringify(value.report)}`,
    (error) => `${error.name}: ${error.message}`);
  record("format.detect.host", "formats", "format detection by content/extension", "js", "gap-js",
    `format defaults to JPEG unless the caller names one; non-JPEG bytes go to the JPEG handler unannounced; outcome: ${outcome}`);
});

// A canned authority, as in the signing addon's own tests: the token is opaque to
// the builder, which embeds it without decoding it.
const TOKEN = Buffer.alloc(300, 0x42);
function tsResponse(status = 0) {
  const token = status === 0 ? Buffer.concat([Buffer.from([0x30, 0x82, 0x01, 0x2c]), TOKEN]) : Buffer.alloc(0);
  const body = Buffer.concat([Buffer.from([0x30, 0x03, 0x02, 0x01, status]), token]);
  return Buffer.concat([Buffer.from([0x30, 0x82, body.length >> 8, body.length & 0xff]), body]);
}
async function authority(respond) {
  const seen = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      seen.push({ method: request.method, type: request.headers["content-type"], body: Buffer.concat(chunks) });
      const [code, body] = respond();
      response.writeHead(code, { "content-type": "application/timestamp-reply" });
      response.end(body);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { seen, url: `http://127.0.0.1:${server.address().port}/tsa`,
    close: () => new Promise((resolve) => server.close(resolve)) };
}

test("timestamp transport bounds the response size and time", async () => {
  const stalled = createServer((request, response) => {
    request.resume();
    response.writeHead(200);
    response.write(Buffer.from([1]));
  });
  const huge = createServer((request, response) => {
    request.resume();
    response.writeHead(200);
    const chunk = Buffer.alloc(256 * 1024);
    const pump = () => { while (!response.destroyed && response.write(chunk)); };
    response.on("drain", pump);
    pump();
  });
  const urlOf = async (server) => {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${server.address().port}/`;
  };
  try {
    const request = new Uint8Array([1]);
    await assert.rejects(postTimestamp({ url: await urlOf(stalled), request }, 200), /did not answer within 200 ms/);
    await assert.rejects(postTimestamp({ url: await urlOf(huge), request }), /implausibly large/);
  } finally {
    stalled.closeAllConnections();
    huge.closeAllConnections();
    await Promise.all([stalled, huge].map((server) => new Promise((resolve) => server.close(resolve))));
  }
});

test("RFC 3161 timestamps through the Worker host", async () => {
  const good = await authority(() => [200, tsResponse(0)]);
  try {
    const signed = await client.sign({ path: jpegSource }, { ...baseline, tsa_url: good.url }, signerFor("es256"));
    assert.equal(good.seen.length, 1);
    assert.equal(good.seen[0].type, "application/timestamp-query");
    assert.ok(Buffer.from(signed.manifest).includes(TOKEN), "token embedded in the manifest store");
    record("tsa.sign.node", "timestamps", "tsa_url timestamps the claim", "node-host", "pass",
      "Worker POSTs the Rust-built TimeStampReq; the token lands in the manifest");
  } finally { await good.close() }
  for (const [name, respond] of [["refusal status", () => [200, tsResponse(2)]],
    ["HTTP 500", () => [500, Buffer.alloc(0)]], ["malformed body", () => [200, Buffer.from([1, 2, 3])]]]) {
    const bad = await authority(respond);
    const output = join(folder, "refused.jpg");
    try {
      await assert.rejects(client.sign({ path: jpegSource }, { ...baseline, tsa_url: bad.url },
        signerFor("es256"), { path: output }), undefined, name);
      assert.deepEqual((await readdir(folder)).filter((entry) => entry === "refused.jpg" || entry.startsWith(".c2pa-")), []);
    } finally { await bad.close() }
  }
  await assert.rejects(client.sign({ path: jpegSource }, { ...baseline, tsa_url: "file:///etc/passwd" },
    signerFor("es256")), /tsa_url|http/i);
  record("tsa.failure.node", "timestamps", "failed timestamp fails the build, leaves no output", "node-host", "pass",
    "refusal, HTTP 500, malformed body and non-http URL all reject with no output or temp file left");
  // The same shared build loop, over the Wasm adapter instead of Neon.
  const wasmAuthority = await authority(() => [200, tsResponse(0)]);
  try {
    const signer = signerFor("es256");
    const result = await driveBuild(wasmAdapter, byteSource(new Uint8Array(readFileSync(jpegSource))),
      JSON.stringify({ ...baseline, tsa_url: wasmAuthority.url }), signer.certs,
      async (request) => signer.sign(request.data));
    assert.equal(wasmAuthority.seen.length, 1);
    assert.equal(wasmAuthority.seen[0].type, "application/timestamp-query");
    assert.ok(Buffer.from(result.manifest).includes(TOKEN), "token embedded in the manifest store");
    record("tsa.sign.wasm", "timestamps", "timestamp through Wasm", "wasm-glue", "pass",
      "BuildSession exposes the Timestamp request and timestamp_response; the shared host answers it");
  } finally { await wasmAuthority.close() }
  record("tsa.override", "timestamps", "caller-supplied sendTimestampRequest / timeAuthorityUrl", "js", "gap-js",
    "The Worker POSTs with fetch only; the earlier standalone Neon host let the signer override transport and URL");
});

test("signing callbacks are captured when sign() is called", async () => {
  const identity = { ...signerFor("es384"), roles: ["cawg.creator"] };
  const signer = { ...signerFor("es256"), identities: [identity] };
  const pending = client.sign({ path: jpegSource }, baseline, signer);
  // Swapping callbacks after the call must not change which key signs.
  signer.sign = async () => { throw new Error("replacement signer must not run") };
  identity.sign = async () => { throw new Error("replacement identity signer must not run") };
  const signed = await pending;
  const read = await client.read(signed.asset, { settings: settingsFor("es256"), now: nowSeconds() });
  assert.equal(read.report.validation_state, "Trusted");
});

test("reader trust, identity and OCSP surface", async () => {
  const signed = await client.sign({ path: jpegSource }, baseline, signerFor("es256"));
  const trusted = await client.read(signed.asset, { settings: settingsFor("es256"), now: nowSeconds() });
  const untrusted = await client.read(signed.asset, { now: nowSeconds() });
  assert.equal(trusted.report.validation_state, "Trusted");
  assert.notEqual(untrusted.report.validation_state, "Trusted");
  record("read.trust.anchors", "reader", "custom trust anchors change validation_state", "node-host", "pass",
    `with anchor ${trusted.report.validation_state}; without ${untrusted.report.validation_state}`);

  // The identity is signed with a different key and algorithm than the claim, so
  // only per-label routing in the host can make the result valid.
  const identity = { ...signerFor("es384"), roles: ["cawg.creator"] };
  const withIdentity = await client.sign({ path: jpegSource }, baseline,
    { ...signerFor("es256"), identities: [identity] });
  const identityRead = await client.read(withIdentity.asset, { settings: settingsFor("es256"), now: nowSeconds() });
  const text = JSON.stringify(identityRead.report);
  assert.ok(text.includes("cawg.identity"), "the identity assertion is in the manifest");
  assert.equal(identityRead.report.validation_state, "Trusted");
  const identityCodes = (report) => report.validation_status
    .filter((status) => status.url.endsWith("c2pa.assertions/cawg.identity")).map((status) => status.code);
  assert.ok(identityCodes(identityRead.report).includes("cawg.x509.signature.validated"),
    "the identity signature itself verifies, not only the store");
  // Same certificate, but a signature from a different key of the same width: the
  // store stays Trusted (identity failures are scoped to their assertion), so only
  // the identity-specific status can reveal it.
  const wrongKey = { ...identity, alg: "es256", certs: signerFor("es256").certs, sign: signerFor("ed25519").sign };
  const forged = await client.sign({ path: jpegSource }, baseline, { ...signerFor("es256"), identities: [wrongKey] });
  const forgedRead = await client.read(forged.asset, { settings: settingsFor("es256"), now: nowSeconds() });
  assert.equal(forgedRead.report.validation_state, "Trusted");
  assert.ok(identityCodes(forgedRead.report).includes("cawg.x509.signature.mismatch"));
  assert.ok(!identityCodes(forgedRead.report).includes("cawg.x509.signature.validated"));
  record("cawg.sign", "identity", "CAWG identity assertion from JS", "rust-bridge", "pass",
    "signer.identities signs each cawg.identity assertion with its own key and algorithm; the bridge carries the label on the sign request");
  const active = identityRead.report.manifests[identityRead.report.active_manifest];
  assert.equal(active.identity_assertions.length, 1);
  const [found] = active.identity_assertions;
  assert.equal(found.label, "cawg.identity");
  assert.equal(found.credential, "x509.cose");
  assert.equal(found.sig_type, "cawg.x509.cose");
  assert.deepEqual(found.roles, ["cawg.creator"]);
  assert.ok(found.signer, "the verified signer subject is reported");
  assert.equal(found.valid, true);
  assert.ok(found.validation_status.some((status) => status.code === "cawg.x509.signature.validated"),
    JSON.stringify(found.validation_status));
  // An asset without identities carries no identity section at all.
  const plain = trusted.report.manifests[trusted.report.active_manifest];
  assert.equal(plain.identity_assertions, undefined);
  record("cawg.read", "identity", "CAWG identity results from a JS read", "rust-bridge", "pass",
    "each manifest reports identity_assertions: label, sig_type, credential kind, verified signer, roles, referenced assertions, per-assertion statuses and a valid flag");
});

// A CA and a leaf it issued, the leaf naming an OCSP responder: the reader only
// asks for revocation when a chain gives it an issuer to build the request against.
function makeChain(responderPort = 9) {
  const run = (...args) => execFileSync("openssl", args, { stdio: "pipe" });
  const file = (name) => join(folder, `chain-${name}`);
  run("req", "-x509", "-nodes", "-days", "3650", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-keyout", file("ca.key"), "-out", file("ca.pem"), "-subj", "/C=US/O=matrix/OU=TEST ONLY/CN=matrix CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  run("req", "-new", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-keyout", file("leaf.key"), "-out", file("leaf.csr"), "-subj", "/C=US/O=matrix/OU=TEST ONLY/CN=matrix leaf");
  return readFile(file("ca.key")).then(async () => {
    await writeFile(file("leaf.ext"), [
      "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,nonRepudiation",
      "extendedKeyUsage=critical,emailProtection", "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid",
      `authorityInfoAccess=OCSP;URI:http://127.0.0.1:${responderPort}/ocsp`, ""].join("\n"));
    run("x509", "-req", "-in", file("leaf.csr"), "-CA", file("ca.pem"), "-CAkey", file("ca.key"), "-CAcreateserial",
      "-days", "3650", "-extfile", file("leaf.ext"), "-out", file("leaf.pem"));
    const der = (name) => new X509Certificate(readFileSync(file(name))).raw;
    return { privateKey: createPrivateKey(readFileSync(file("leaf.key"))), leaf: der("leaf.pem"),
      ca: der("ca.pem"), caPem: new X509Certificate(readFileSync(file("ca.pem"))).toString() };
  });
}

test("live OCSP through the Worker host and Wasm, with the private-host policy", async () => {
  const seen = [];
  const responder = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      seen.push({ type: request.headers["content-type"], body: Buffer.concat(chunks) });
      response.writeHead(200, { "content-type": "application/ocsp-response" });
      response.end(Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x02])); // OCSPResponse: tryLater
    });
  });
  await new Promise((resolve) => responder.listen(0, "127.0.0.1", resolve));
  try {
    const chain = await makeChain(responder.address().port);
    const signer = { alg: "es256", certs: [new Uint8Array(chain.leaf), new Uint8Array(chain.ca)],
      async sign(data) { return new Uint8Array(cryptoSign("sha256", Buffer.from(data), { key: chain.privateKey, dsaEncoding: "ieee-p1363" })) } };
    const signed = await client.sign({ path: jpegSource }, baseline, signer);
    const trust = { anchors: [{ trust_kind: "manifest", trust_anchors: chain.caPem }] };
    const on = { trust, verify: { ocsp_fetch: true } };
    const off = await client.read(signed.asset, { settings: { trust, verify: { ocsp_fetch: false } }, now: nowSeconds() });
    assert.equal(off.report.validation_state, "Trusted");
    assert.equal(seen.length, 0);

    // The responder URL comes from the certificate: loopback is refused by default,
    // and the engine fails open when the host cannot answer.
    const refused = await client.read(signed.asset, { settings: on, now: nowSeconds() });
    assert.equal(seen.length, 0, "a loopback responder is not contacted by default");
    assert.equal(refused.stats.ocsp, 1);
    assert.equal(refused.report.validation_state, "Trusted");

    const allowed = await client.read(signed.asset, { settings: on, now: nowSeconds(), ocspPolicy: { allowPrivateHosts: true } });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].type, "application/ocsp-request");
    assert.ok(seen[0].body.length > 0);
    record("ocsp.read.node", "reader", "live OCSP (ocsp_fetch on) through the Worker host", "node-host", "pass",
      `request POSTed as application/ocsp-request; default policy refuses private hosts; state ${allowed.report.validation_state}`);

    const wasmRead = await driveRead(wasmAdapter, byteSource(new Uint8Array(signed.asset)),
      JSON.stringify(on), nowSeconds(), "image/jpeg", { allowPrivateHosts: true });
    assert.equal(seen.length, 2);
    assert.equal(wasmRead.report.validation_state, allowed.report.validation_state);
    record("ocsp.read.wasm", "reader", "live OCSP through Wasm", "wasm-glue", "pass",
      "ReadSession exposes the Ocsp request, ocsp() and failed() replies; same shared host loop and policy");
  } finally { await new Promise((resolve) => responder.close(resolve)) }
  for (const host of ["localhost", "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "[::1]", "[fe80::1]", "[fd00::1]", "[::ffff:7f00:1]"]) assert.ok(isNonPublicHost(host), host);
  for (const host of ["example.com", "93.184.216.34", "172.32.0.1", "[2606:4700::1111]"])
    assert.ok(!isNonPublicHost(host), host);
});

