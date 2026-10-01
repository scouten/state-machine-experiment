import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import test from "node:test";

import { _native, answerRequest, openSource, Reader } from "../index.mjs";

const PATH = new URL("../../contentauth-c2pa-reader/tests/fixtures/C.jpg", import.meta.url)
  .pathname;
const BYTES = readFileSync(PATH);
// Inside every certificate's validity window, and not the wall clock, so a
// pass proves the *host's* clock was the one the engine used.
const now = () => 1_800_000_000_000;

/** An asset whose reads genuinely take time, and which records concurrency. */
function slowAsset(delayMs = 5, stats = { reads: 0, inFlight: 0, maxInFlight: 0 }) {
  return {
    stats,
    size: BYTES.length,
    async read(start, len) {
      stats.reads++;
      stats.maxInFlight = Math.max(stats.maxInFlight, ++stats.inFlight);
      await sleep(delayMs);
      stats.inFlight--;
      return BYTES.subarray(start, start + len);
    },
  };
}

test("reads a signed JPEG from a path, a buffer, and an async source alike", async () => {
  const fromPath = await Reader.fromAsset({ path: PATH }, null, { now });
  const fromBuffer = await Reader.fromAsset({ buffer: BYTES, mimeType: "image/jpeg" }, null, { now });
  const fromSource = await Reader.fromAsset(slowAsset(), null, { now });

  assert.ok(fromPath.activeLabel());
  assert.equal(fromPath.json().validation_state, "Valid");
  assert.deepEqual(fromBuffer.json(), fromPath.json());
  assert.deepEqual(fromSource.json(), fromPath.json());
  assert.equal(fromPath.getActive().label, fromPath.activeLabel());
  assert.equal(fromPath.isEmbedded(), true);
  assert.equal(fromPath.remoteUrl(), "");
});

test("the format is sniffed from the bytes when no mime type or extension is given", async () => {
  const reader = await Reader.fromAsset({ buffer: BYTES }, null, { now });
  assert.ok(reader.activeLabel());
});

test("an asset with no manifest store resolves to null, as in c2pa-node", async () => {
  const bare = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
  assert.equal(await Reader.fromAsset({ buffer: bare, mimeType: "image/jpeg" }), null);
});

test("errors carry c2pa-rs's Debug string as their name", async () => {
  await assert.rejects(
    Reader.fromAsset({ buffer: BYTES, mimeType: "image/png" }),
    { name: "C2pa(UnsupportedType)" },
  );
  await assert.rejects(
    Reader.fromAsset({ buffer: BYTES, mimeType: "image/jpeg" }, "{not json"),
    (err) => err.name.startsWith("C2pa(BadParam("),
  );
  await assert.rejects(Reader.fromAsset({ path: "/no/such/file.jpg" }), { code: "ENOENT" });
});

test("the host decides how many requests run at once", async () => {
  const unlimited = slowAsset();
  await Reader.fromAsset(unlimited, null, { now });
  assert.ok(unlimited.stats.maxInFlight > 1, JSON.stringify(unlimited.stats));

  const serial = slowAsset();
  await Reader.fromAsset(serial, null, { now, concurrency: 1 });
  assert.equal(serial.stats.maxInFlight, 1);
  assert.equal(serial.stats.reads, unlimited.stats.reads);

  const two = slowAsset();
  await Reader.fromAsset(two, null, { now, concurrency: 2 });
  assert.equal(two.stats.maxInFlight, 2);
});

test("the JS thread is never blocked: timers fire throughout a slow read", async () => {
  const asset = slowAsset(20);
  let ticks = 0;
  const timer = setInterval(() => ticks++, 1);
  const started = performance.now();
  await Reader.fromAsset(asset, null, { now, concurrency: 1 });
  clearInterval(timer);

  const elapsed = performance.now() - started;
  assert.ok(elapsed >= 20 * asset.stats.reads * 0.9, `${elapsed}ms`);
  assert.ok(ticks > asset.stats.reads, `${ticks} ticks over ${asset.stats.reads} reads`);
});

test("many reads interleave on the one thread", async () => {
  // How much overlap does one read achieve by itself?
  const alone = slowAsset(10);
  await Reader.fromAsset(alone, null, { now });

  // Eight reads sharing one counter: requests from *different* reads must
  // be in flight together, beyond anything a single read reaches. (Counted,
  // not timed: wall-clock bounds are meaningless in an unoptimized build.)
  const shared = { reads: 0, inFlight: 0, maxInFlight: 0 };
  const assets = Array.from({ length: 8 }, () => slowAsset(10, shared));
  const readers = await Promise.all(assets.map((a) => Reader.fromAsset(a, null, { now })));

  for (const reader of readers) assert.equal(reader.json().validation_state, "Valid");
  assert.ok(
    shared.maxInFlight > alone.stats.maxInFlight,
    `${shared.maxInFlight} in flight across reads vs ${alone.stats.maxInFlight} for one`,
  );
});

test("a source that fails mid-read fails the read, not the process", async () => {
  const asset = { ...slowAsset(), read: async () => { throw new Error("disk on fire"); } };
  await assert.rejects(Reader.fromAsset(asset, null, { now }));
});

test("OCSP requests are answered with fetch: POSTed DER in, response body out", async () => {
  const der = Buffer.from([1, 2, 3]);
  let seen;
  const doFetch = async (url, init) => {
    seen = { url, init };
    return new Response(Buffer.from([4, 5, 6]), { status: 200 });
  };
  const reply = await answerRequest(
    { kind: "ocsp", url: "http://ocsp.example/", requestDer: der },
    { size: 0 },
    { doFetch, now },
  );
  assert.deepEqual(reply, ["ocsp", Buffer.from([4, 5, 6])]);
  assert.equal(seen.url, "http://ocsp.example/");
  assert.equal(seen.init.method, "POST");
  assert.equal(seen.init.headers["content-type"], "application/ocsp-request");
  assert.equal(seen.init.body, der);
});

test("whatever the host cannot do becomes a failed reply, never a rejection", async () => {
  const source = { size: 0, read: async () => { throw new Error("nope"); } };
  const ctx = { doFetch: async () => new Response("", { status: 503 }), now };

  assert.deepEqual(await answerRequest({ kind: "read", start: 0, len: 1 }, source, ctx), ["failed", "nope"]);
  assert.deepEqual(await answerRequest({ kind: "ocsp", url: "u", requestDer: Buffer.alloc(0) }, source, ctx), ["failed", "OCSP responder said 503"]);
  const down = { ...ctx, doFetch: async () => { throw new TypeError("fetch failed"); } };
  assert.deepEqual(await answerRequest({ kind: "ocsp", url: "u", requestDer: Buffer.alloc(0) }, source, down), ["failed", "fetch failed"]);
  assert.deepEqual(await answerRequest({ kind: "bogus" }, source, ctx), ["failed", "unsupported request bogus"]);
  assert.deepEqual(await answerRequest({ kind: "length" }, { size: 7 }, ctx), ["length", 7]);
  assert.deepEqual(await answerRequest({ kind: "time" }, source, ctx), ["time", 1_800_000_000]);
});

test("an unrecognizable asset is rejected up front", async () => {
  await assert.rejects(Reader.fromAsset({}), TypeError);
  // Too short to sniff, and no mime type: no format can be chosen.
  await assert.rejects(Reader.fromAsset({ buffer: Buffer.from([1, 2]) }), {
    name: "C2pa(UnsupportedType)",
  });
});

test("the native binding reports misuse as errors, not crashes", () => {
  const session = _native.sessionNew("image/jpeg");
  assert.throws(() => _native.sessionFulfill(session, 12345, "length", 1), /no outstanding request/);
  assert.throws(() => _native.sessionFulfill(session, 0, "bogus", 1), /unknown reply kind/);

  const first = _native.sessionAdvance(session).requests[0];
  // A reply of the wrong kind is rejected, and the request stays answerable.
  assert.throws(() => _native.sessionFulfill(session, first.id, "time", 0));
  assert.throws(() => _native.sessionFulfill(session, first.id, "ocsp", Buffer.alloc(0)));
  _native.sessionFulfill(session, first.id, "failed", "no thanks");

});

test("a session that is finished, or not finishable yet, says so", () => {
  const session = _native.sessionNew("image/jpeg", "{}");
  assert.throws(() => _native.sessionFinish(session)); // engine not complete
  assert.throws(() => _native.sessionAdvance(session), /already finished/);
});

test("a file source reads exact ranges, and fails cleanly if the file shrinks underneath it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "c2pa-node-compat-"));
  const path = join(dir, "a.bin");
  try {
    writeFileSync(path, Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]));
    const source = await openSource({ path });
    assert.equal(source.size, 8);
    assert.deepEqual(await source.read(2, 3), Buffer.from([2, 3, 4]));

    truncateSync(path, 4);
    await assert.rejects(source.read(2, 6), /unexpected end of file at 4/);
    await source.close();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test("a malformed container is an engine error, named as c2pa-rs-style Debug", async () => {
  await assert.rejects(
    Reader.fromAsset({ buffer: Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x01]), mimeType: "image/jpeg" }),
    (err) => err.name.startsWith("C2pa(Read(Format(Malformed("),
  );
});

test("a finished session cannot be fulfilled, advanced, or finished again", () => {
  const session = _native.sessionNew("image/jpeg");
  for (;;) {
    const step = _native.sessionAdvance(session);
    if (step.done) break;
    for (const r of step.requests) {
      if (r.kind === "read") _native.sessionFulfill(session, r.id, "bytes", BYTES.subarray(r.start, r.start + r.len));
      else if (r.kind === "length") _native.sessionFulfill(session, r.id, "length", BYTES.length);
      else _native.sessionFulfill(session, r.id, "time", 1_800_000_000);
    }
  }
  assert.ok(_native.sessionFinish(session));
  assert.throws(() => _native.sessionFulfill(session, 0, "length", 1), /already finished/);
  assert.throws(() => _native.sessionAdvance(session), /already finished/);
  assert.throws(() => _native.sessionFinish(session), /already finished/);
});
