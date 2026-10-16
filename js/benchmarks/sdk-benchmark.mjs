function check(value, message) { if (!value) throw new Error(message) }

export function validateReport(report, definition) {
  check(report?.validation_state === "Trusted", `benchmark asset not Trusted: ${JSON.stringify(report?.validation_status)}`);
  const manifest = report.manifests[report.active_manifest];
  check(manifest.title === definition.title, "benchmark title changed");
  check(manifest.assertions.some((assertion) => (typeof assertion === "string" ? assertion : assertion.label) === "c2pa.actions.v2"),
    `missing actions assertion: ${JSON.stringify(manifest.assertions)}`);
  const statuses = report.validation_results?.activeManifest?.success ?? report.validation_status;
  for (const code of ["claimSignature.validated", "signingCredential.trusted", "assertion.dataHash.match"])
    check(statuses.some((status) => status.code === code), `benchmark missing ${code}`);
}

export async function benchmark(adapters, fixtures, signer) {
  const samples = [];
  const validation = [];
  for (const name of ["small", "large"]) {
    const { source, signed, definition } = fixtures[name];
    const tampered = signed.slice();
    tampered[tampered.length - 1] ^= 1;
    for (const adapter of Object.values(adapters)) {
      const report = await adapter.read(tampered);
      await adapter.cleanup?.();
      check(report?.validation_state === "Invalid", `${name}: tampering was not rejected`);
      const failures = report.validation_results?.activeManifest?.failure ?? report.validation_status;
      check(failures?.some((status) => status.code === "assertion.dataHash.mismatch"), "tampered asset missing hash failure");
    }
    for (const operation of ["read", "sign"]) {
      async function run(sdk, iteration, measured) {
        const adapter = adapters[sdk];
        let signCalls = 0;
        let signerMs = 0;
        const signing = async (data) => {
          const started = performance.now();
          try { signCalls++; return await signer(data) }
          finally { signerMs += performance.now() - started }
        };
        const started = performance.now();
        const value = operation === "read"
          ? await adapter.read(signed)
          : await adapter.sign(source, definition, signing);
        const totalMs = performance.now() - started;
        await adapter.cleanup?.();
        if (operation === "read") validateReport(value, definition);
        else {
          check(signCalls === 1, "benchmark signer call count changed");
          check(value.asset instanceof Uint8Array && value.manifest instanceof Uint8Array, "missing signed bytes");
          // Both validators must accept every produced asset. Validation is
          // deliberately outside the measured signing interval.
          for (const reader of Object.values(adapters)) {
            validateReport(await reader.read(value.asset), definition);
            await reader.cleanup?.();
          }
        }
        if (measured) samples.push({ name, operation, sdk, iteration, totalMs, signerMs,
          inputBytes: operation === "read" ? signed.length : source.length,
          outputBytes: operation === "sign" ? value.asset.length : undefined,
          manifestBytes: operation === "sign" ? value.manifest.length : undefined });
      }
      for (let warmup = 0; warmup < 2; warmup++)
        for (const sdk of ["existing", "proof"]) await run(sdk, warmup, false);
      for (let iteration = 0; iteration < 6; iteration++)
        for (const sdk of iteration % 2 ? ["proof", "existing"] : ["existing", "proof"])
          await run(sdk, iteration, true);
      validation.push(`${name} ${operation}: both SDK reports Trusted; sign outputs cross-validated; tampering rejected by both`);
    }
  }
  return { methodology: "2 warmups per SDK/size/operation; 6 alternating-order measured pairs; full reports; signing includes builder creation; validation/free outside timing; warm runtimes; sequential",
    samples, validation };
}

// Existing c2pa-web requires a complete, padded COSE_Sign1 response, unlike
// the proof and Node CallbackSigner raw-signature APIs. This benchmark-only
// adapter creates that envelope with the same application WebCrypto key.
export async function coseSigner(claim, reserveSize, cert, sign) {
  function cbor(value) {
    function head(major, length) {
      if (length < 24) return [major * 32 + length];
      if (length < 256) return [major * 32 + 24, length];
      if (length < 65536) return [major * 32 + 25, length >> 8, length & 255];
      throw new Error("benchmark CBOR item too large");
    }
    if (value === null) return new Uint8Array([246]);
    if (typeof value === "number") return new Uint8Array(head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value));
    if (typeof value === "string") {
      const bytes = new TextEncoder().encode(value);
      return new Uint8Array([...head(3, bytes.length), ...bytes]);
    }
    if (value instanceof Uint8Array) return new Uint8Array([...head(2, value.length), ...value]);
    if (Array.isArray(value)) return new Uint8Array([...head(4, value.length), ...value.flatMap((item) => Array.from(cbor(item)))]);
    if (value instanceof Map) return new Uint8Array([...head(5, value.size),
      ...Array.from(value).flatMap(([key, item]) => [...cbor(key), ...cbor(item)])]);
    throw new Error("unsupported benchmark CBOR value");
  }
  const protectedBytes = cbor(new Map([[1, -7], [33, cert]]));
  const signature = await sign(cbor(["Signature1", protectedBytes, new Uint8Array(), claim]));
  const encode = (padding) => new Uint8Array([210,
    ...cbor([protectedBytes, new Map([["pad", new Uint8Array(padding)]]), null, signature])]);
  let padding = reserveSize - encode(0).length;
  for (let attempt = 0; attempt < 4; attempt++) {
    check(padding >= 0, "COSE reserve too small");
    const result = encode(padding);
    if (result.length === reserveSize) return result;
    padding += reserveSize - result.length;
  }
  throw new Error("could not pad benchmark COSE response");
}
