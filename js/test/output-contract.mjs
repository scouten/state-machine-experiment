import { BlobOutput, ArrayOutput, buildWithOutput } from "./blob-output.mjs";
import { build as productionBuild } from "../src/shared/drive.mjs";

const check = (value, message) => { if (!value) throw new Error(message) };
const equal = (a, b, message) => check(JSON.stringify(a) === JSON.stringify(b), message);

async function readBlob(adapter, blob, fixture) {
  const session = adapter.create(JSON.stringify(fixture.settings));
  const stats = { reads: 0, bytes: 0, maxReadBytes: 0, maxReadEnd: 0 };
  try {
    for (;;) {
      const step = session.advance();
      if (step.done) return { report: JSON.parse(session.finish()), stats };
      check(step.requests.length, "readback stalled");
      for (const request of step.requests) {
        if (request.kind === "read") {
          check(Number.isSafeInteger(request.start) && Number.isSafeInteger(request.len) &&
            request.start >= 0 && request.len >= 0 && request.start + request.len <= blob.size,
          "readback out of bounds");
          const bytes = new Uint8Array(await blob.slice(request.start, request.start + request.len).arrayBuffer());
          check(bytes.length === request.len, "short readback");
          stats.reads++;
          stats.bytes += bytes.length;
          stats.maxReadBytes = Math.max(stats.maxReadBytes, bytes.length);
          stats.maxReadEnd = Math.max(stats.maxReadEnd, request.start + bytes.length);
          session.fulfill(request.id, "bytes", bytes);
        } else if (request.kind === "length") session.fulfill(request.id, "length", blob.size);
        else if (request.kind === "time") session.fulfill(request.id, "time", fixture.now);
        else throw new Error(`unsupported readback request: ${request.kind}`);
      }
    }
  } finally { session.close() }
}

// A test-only direct session host, not a new Client/sign result API. Uses main's
// Uint8Array source and ordinary read/write requests, independent of range inputs.
export async function outputContract(adapter, fixture, pkcs8) {
  const key = await crypto.subtle.importKey("pkcs8", pkcs8,
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const certs = fixture.signing.certs.map((cert) => new Uint8Array(cert));
  const samples = [];
  for (const name of ["small", "large"]) {
    const input = new Uint8Array(fixture.signing.files[name].sourceBytes);
    input.set([255, 216, 255, 217]);
    // Sign once outside both timed hosts: same valid signature, no ECDSA
    // randomness or first-variant crypto cost in the storage comparison.
    const signature = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, key,
      new Uint8Array(fixture.signing.files[name].requests[0].data)));
    const sign = async ({ data, alg }) => {
      check(alg === "es256", "wrong signer algorithm");
      equal(Array.from(data), fixture.signing.files[name].requests[0].data, "COSE input changed");
      return signature;
    };
    const rows = [];
    let control;
    for (const Storage of [ArrayOutput, BlobOutput]) {
      const output = new Storage();
      const started = performance.now();
      const result = await buildWithOutput(adapter, input, fixture.signing.definition, certs, sign, output);
      const ms = performance.now() - started;
      const stats = { ...result.stats };
      check(stats.patchWrites > 0 && stats.patchedBytes > 0, "final manifest patch not exercised");
      equal(result.exclusions.map(({ start, len }) => ({ start, len })),
        fixture.signing.files[name].exclusions, "hash exclusions changed");
      check(result.manifest.length === fixture.signing.files[name].manifestBytes, "manifest length changed");
      if (Storage === ArrayOutput) control = result.asset;
      else {
        check(result.asset instanceof Blob, "experiment output must be Blob");
        check(result.asset.size === control.length && control.length === fixture.files[name].bytes,
          "logical output length/stale tail");
        for (let offset = 0; offset < control.length; offset += 1024 * 1024) {
          const bytes = await output.read(offset, Math.min(1024 * 1024, control.length - offset));
          check(bytes.every((byte, i) => byte === control[offset + i]), "patch bytes differ from control");
        }
      }
      const blob = result.asset instanceof Blob ? result.asset : new Blob([result.asset]);
      const readback = await readBlob(adapter, blob, fixture);
      equal(readback.report, fixture.files[name].report, "full readback differs from fixture");
      check(readback.report.validation_state === "Trusted", "readback not Trusted");
      check(stats.maxReadEnd <= blob.size && readback.stats.maxReadEnd <= blob.size, "read past logical end");
      rows.push({ storage: Storage.name, ms, outputBytes: blob.size, stats, readback: readback.stats });
    }
    if (name === "small") {
      const production = await productionBuild(adapter, input, JSON.stringify(fixture.signing.definition), certs, sign);
      check(production.asset instanceof Uint8Array, "production default result changed");
      check(production.asset.every((byte, i) => byte === control[i]), "array control differs from production");
    }
    samples.push({ name, sourceBytes: input.length, rows });
  }
  return { samples, caveat: "Explicit JS copy counters, not physical Blob copies, allocations, or peak RSS. Test-only direct host; public output remains Uint8Array." };
}
