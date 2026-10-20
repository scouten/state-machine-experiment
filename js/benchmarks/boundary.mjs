function check(value, message) { if (!value) throw new Error(message) }
function equal(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(message);
}

// Paired, alternating-order measurements in one browser process and Wasm build.
// Only the browser binding's write-payload representation differs.
export async function boundaryComparison(createClient, fixture, pkcs8) {
  const key = await crypto.subtle.importKey("pkcs8", pkcs8,
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const clients = { json: createClient({ transport: "json" }), binary: createClient({ transport: "binary" }) };
  const samples = [];
  const source = (name) => {
    const bytes = new Uint8Array(fixture.signing.files[name].sourceBytes);
    bytes.set([255, 216, 255, 217]);
    return bytes;
  };
  const sources = { small: source("small"), large: source("large") };
  const expectedStats = {};
  async function run(transport, name, measured, iteration) {
    const client = clients[transport];
    let calls = 0;
    let signerMs = 0;
    const signer = {
      alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
      async sign(data) {
        const expected = fixture.signing.files[name].requests[calls++];
        check(expected?.alg === this.alg, "boundary comparison algorithm changed");
        equal(Array.from(data), expected.data, "boundary comparison signing input changed");
        const started = performance.now();
        const signature = new Uint8Array(await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" }, key, data));
        signerMs += performance.now() - started;
        return signature;
      },
    };
    const started = performance.now();
    const result = await client.sign(sources[name], fixture.signing.definition, signer);
    const totalMs = performance.now() - started;
    check(calls === 1, "boundary comparison signer call count changed");
    check(result.asset.length === fixture.files[name].bytes, "boundary comparison output length changed");
    check(result.manifest.length === fixture.signing.files[name].manifestBytes, "manifest length changed");
    equal(result.exclusions.map(({ start, len }) => ({ start, len })),
      fixture.signing.files[name].exclusions, "boundary comparison exclusions changed");
    expectedStats[name] ??= result.stats;
    equal(result.stats, expectedStats[name], "boundary comparison request accounting changed");
    check(result.boundary.transport === transport, "wrong boundary selected");
    check(result.boundary.writePayloadBytes === result.stats.writtenBytes, "boundary byte accounting changed");
    check(result.boundary.writes === result.stats.writes, "boundary write accounting changed");
    // Validate outside the measured build interval.
    const { report } = await client.read(result.asset, { settings: fixture.settings, now: fixture.now });
    equal(report, fixture.files[name].report, "boundary comparison trusted report changed");
    if (measured) samples.push({ transport, name, iteration, totalMs, workerMs: result.workerMs,
      signerMs, inputBytes: sources[name].length, outputBytes: result.asset.length,
      stats: result.stats, boundary: result.boundary });
  }
  try {
    for (const name of ["small", "large"]) {
      for (const transport of ["json", "binary"]) await run(transport, name, false, -1);
      for (let iteration = 0; iteration < 4; iteration++) {
        for (const transport of iteration % 2 ? ["binary", "json"] : ["json", "binary"])
          await run(transport, name, true, iteration);
      }
    }
    return { order: "four paired iterations per size, alternating json/binary first; one warmup per size/transport",
      instrumentation: "wasmAdvanceMs includes Rust work, serialization and string transfer; parseMs is JSON.parse; payloadMs includes byte conversion/copy and request normalization",
      samples };
  } finally { await Promise.all(Object.values(clients).map((client) => client.dispose())) }
}
