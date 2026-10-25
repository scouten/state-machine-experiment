// Real Worker/Neon and Worker/Wasm acceptance, with actual completed source I/O
// accounting (not process memory or inferred allocations).
export async function rangeContract(createClient, signed, source, fixture, pkcs8) {
  const check = (value, message) => { if (!value) throw new Error(message) };
  const equal = (a, b) => check(JSON.stringify(a) === JSON.stringify(b), "range result differs");
  const client = createClient();
  const options = { settings: fixture.settings, now: fixture.now };
  const key = await crypto.subtle.importKey("pkcs8", pkcs8,
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signer = {
    alg: "es256", certs: fixture.signing.certs.map((cert) => new Uint8Array(cert)),
    async sign(data) {
      equal(Array.from(data), fixture.signing.files.large.requests[0].data);
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
    },
  };
  try {
    const read = await client.read(signed, options);
    equal(read.report, fixture.files.large.report);
    equal(read.stats, fixture.files.large.stats);
    check(read.stats.maxReadEnd <= read.stats.sourceLength, "read past input end");
    check(read.stats.maxReadBytes < read.stats.sourceLength, "whole input read");
    const built = await client.sign(source, fixture.signing.definition, signer);
    check(built.asset instanceof Uint8Array, "default output changed");
    equal(built.exclusions.map(({ start, len }) => ({ start, len })),
      fixture.signing.files.large.exclusions);
    check(built.asset.length === fixture.files.large.bytes, "stale output tail");
    equal((await client.read(built.asset, options)).report, fixture.files.large.report);
    check(built.stats.sourceMaxReadEnd <= built.stats.sourceLength, "sign read past input end");
    check(built.stats.sourceMaxReadBytes <= 1024 * 1024, "unbounded source signing read");
    check(built.stats.sourceBytes >= built.stats.sourceLength, "source copy not accounted");
    const failure = client.sign(source, fixture.signing.definition, {
      ...signer, sign() { throw new Error("range signer failure") },
    });
    const queued = client.read(signed, options);
    try { await failure; throw new Error("missing signer error") }
    catch (error) { check(error.message === "range signer failure", "wrong signer error") }
    equal((await queued).report, read.report);
    check((await client.read(source, options)).report === null, "unsigned range source must return null");
    try {
      await client.read(signed, { ...options, settings: { verify: { ocsp_fetch: "invalid" } } });
      throw new Error("missing settings error");
    } catch (error) { check(/BadParam|invalid|expected/i.test(error.message), "wrong settings error") }
    const pending = client.read(signed, options).then(
      () => { throw new Error("pending range read survived disposal") },
      (error) => check(/disposed/.test(error.message), "wrong disposal error"));
    await client.dispose();
    await pending;
    return { read: read.stats, sign: built.stats, trusted: true, outputBytes: built.asset.length };
  } finally { await client.dispose() }
}
