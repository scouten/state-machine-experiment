function check(value, message) { if (!value) throw new Error(message) }
function equal(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(message);
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done });
  return { promise, resolve };
}
async function within(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("signing proof timed out")), 60_000);
    })]);
  } finally { clearTimeout(timer) }
}
async function rejects(promise, pattern) {
  try { await within(promise) }
  catch (error) {
    check(pattern.test(`${error.name}: ${error.message}`), `unexpected error: ${error}`);
    return;
  }
  throw new Error("expected rejection");
}

// One acceptance contract, including the application-side WebCrypto signer,
// executed unchanged in Node and browsers.
export async function signingContract(createClient, fixture, pkcs8) {
  const key = await crypto.subtle.importKey("pkcs8", pkcs8,
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  check(!key.extractable, "test signing key must be non-extractable");
  const baseline = fixture.signing;
  const options = { settings: fixture.settings, now: fixture.now };
  const source = (name) => {
    const bytes = new Uint8Array(baseline.files[name].sourceBytes);
    bytes.set([255, 216, 255, 217]);
    return bytes;
  };
  function signer(name, hook = async () => {}) {
    let calls = 0;
    return {
      alg: "es256",
      certs: baseline.certs.map((cert) => new Uint8Array(cert)),
      get calls() { return calls },
      async sign(data) {
        const expected = baseline.files[name].requests[calls++];
        check(expected?.alg === this.alg, "signer algorithm differs from direct host");
        equal(Array.from(data), expected.data, "COSE signer input differs from direct host");
        await hook(data);
        return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data));
      },
    };
  }
  async function validate(client, result, name) {
    check(result.asset instanceof Uint8Array, "missing signed output bytes");
    check(result.manifest instanceof Uint8Array, "missing manifest bytes");
    check(result.asset.length === fixture.files[name].bytes, "signed output length differs");
    check(result.manifest.length === baseline.files[name].manifestBytes, "manifest length differs");
    equal(result.exclusions.map(({ start, len }) => ({ start, len })),
      baseline.files[name].exclusions, "hard-binding exclusions differ");
    const { report } = await within(client.read(result.asset, options));
    equal(report, fixture.files[name].report, "signed read-back differs from direct host");
    check(report.validation_state === "Trusted", "signed read-back is not Trusted");
    for (const code of ["claimSignature.validated", "signingCredential.trusted", "assertion.dataHash.match"])
      check(report.validation_status.some((status) => status.code === code), `missing ${code}`);
  }

  const client = createClient();
  const samples = [];
  try {
    const bytes = source("small");
    const definition = structuredClone(baseline.definition);
    const signing = signer("small");
    const first = client.sign(bytes, definition, signing);
    bytes.fill(0);
    definition.title = "mutated after invocation";
    signing.certs[0].fill(0);
    const result = await within(first);
    check(signing.calls === 1, "expected exactly one signer call");
    check(bytes.byteLength === 4, "source detached");
    await validate(client, result, "small");

    const entered = deferred();
    const release = deferred();
    let ticks = 0;
    let settled = false;
    const timer = setInterval(() => { ticks++ }, 1);
    try {
      const delayed = client.sign(source("small"), baseline.definition,
        signer("small", async () => { entered.resolve(); await release.promise }));
      delayed.then(() => { settled = true }, () => { settled = true });
      await within(entered.promise);
      await new Promise((resolve) => setTimeout(resolve, 25));
      check(ticks > 0 && !settled, "pending signer must allow application tasks without completing build");
      release.resolve();
      await validate(client, await within(delayed), "small");
    } finally { release.resolve(); clearInterval(timer) }

    for (const sign of [
      () => { throw new TypeError("synchronous signer failure") },
      async () => { throw new RangeError("async signer rejection") },
    ]) {
      await rejects(client.sign(source("small"), baseline.definition,
        { ...signer("small"), sign }), /TypeError: synchronous signer failure|RangeError: async signer rejection/);
    }
    for (const value of [null, new Uint8Array(63)]) {
      await rejects(client.sign(source("small"), baseline.definition,
        { ...signer("small"), sign: async () => value }), /64 raw signature bytes/);
    }
    const badSignature = await within(client.sign(source("small"), baseline.definition,
      { ...signer("small"), sign: async () => new Uint8Array(64) }));
    check((await within(client.read(badSignature.asset, options))).report.validation_state === "Invalid",
      "a correctly sized but invalid signature must not read back Trusted");
    let unexpectedCalls = 0;
    await rejects(client.sign(source("small"), "{bad json",
      { ...signer("small"), sign() { unexpectedCalls++; throw new Error("unexpected signer") } }), /Definition|JSON|json/);
    check(unexpectedCalls === 0, "invalid definition reached signer");
    await validate(client, await within(client.sign(source("small"), baseline.definition, signer("small"))), "small");

    const queueEntered = deferred();
    const queueRelease = deferred();
    let secondCalls = 0;
    try {
      const first = client.sign(source("small"), baseline.definition,
        signer("small", async () => { queueEntered.resolve(); await queueRelease.promise }));
      await within(queueEntered.promise);
      const second = client.sign(source("large"), baseline.definition,
        signer("large", async () => { secondCalls++ }));
      const read = client.read(result.asset, options);
      await new Promise((resolve) => setTimeout(resolve, 10));
      check(secondCalls === 0, "top-level operations were not serialized");
      queueRelease.resolve();
      const results = await within(Promise.all([first, second, read]));
      await validate(client, results[0], "small");
      await validate(client, results[1], "large");
      equal(results[2].report, fixture.files.small.report, "mixed queued read changed");
      check(secondCalls === 1, "queued signer was not called exactly once");
    } finally { queueRelease.resolve() }

    for (let iteration = 0; iteration < 3; iteration++) {
      let ticks = 0;
      const timer = setInterval(() => { ticks++ }, 1);
      const started = performance.now();
      let measured;
      try {
        measured = await within(client.sign(source("large"), baseline.definition, signer("large")));
        samples.push({ totalMs: performance.now() - started, workerMs: measured.workerMs,
          ticks, inputBytes: baseline.files.large.sourceBytes,
          outputBytes: measured.asset.length, stats: measured.stats });
      } finally { clearInterval(timer) }
      await validate(client, measured, "large");
    }

    const other = createClient();
    const abandonedEntered = deferred();
    const abandonRelease = deferred();
    const callbackReturned = deferred();
    try {
      const abandoned = client.sign(source("small"), baseline.definition, {
        ...signer("small"),
        async sign() {
          abandonedEntered.resolve();
          await abandonRelease.promise;
          callbackReturned.resolve();
          throw new Error("late signer rejection after disposal");
        },
      });
      const rejected = rejects(abandoned, /disposed/);
      await within(abandonedEntered.promise);
      // This other Worker must finish while the first callback is still pending.
      await validate(other, await within(other.sign(source("large"), baseline.definition, signer("large"))), "large");
      await within(client.dispose());
      await rejected;
      abandonRelease.resolve();
      await within(callbackReturned.promise);
      await new Promise((resolve) => setTimeout(resolve, 10));
      await validate(other, await within(other.sign(source("small"), baseline.definition, signer("small"))), "small");
      await rejects(client.sign(source("small"), baseline.definition, signer("small")), /disposed/);
      const lateClient = createClient();
      const lateEntered = deferred();
      const lateRelease = deferred();
      const lateReturned = deferred();
      try {
        const lateSigner = signer("small", async () => { lateEntered.resolve(); await lateRelease.promise });
        const late = lateClient.sign(source("small"), baseline.definition, {
          ...lateSigner,
          async sign(data) {
            const signature = await lateSigner.sign(data);
            lateReturned.resolve();
            return signature;
          },
        });
        const rejected = rejects(late, /disposed/);
        await within(lateEntered.promise);
        await within(lateClient.dispose());
        await rejected;
        // Observe a successful signature too, after disposal has rejected the operation.
        // The caller's async signer still completes; its result must not be posted.
        lateRelease.resolve();
        await within(lateReturned.promise);
        await new Promise((resolve) => setTimeout(resolve, 25));
      } finally { lateRelease.resolve(); await lateClient.dispose() }
    } finally { abandonRelease.resolve(); await other.dispose() }

    return { samples, checks: ["trusted signed read-back/full report", "direct-host signer input/algorithm",
      "source/definition/cert snapshot", "caller-owned non-extractable WebCrypto key", "delayed callback/task progress",
      "sync throw/async reject/retry", "invalid signature reply", "invalid signature reads Invalid",
      "invalid definition before signer",
      "queued mixed operations/request routing", "large signed output", "independent Worker while callback pending",
      "pending disposal/late success and rejection"] };
  } finally { await client.dispose() }
}
