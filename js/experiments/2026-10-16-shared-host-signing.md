# Shared-host signing and asynchronous callbacks

Migrated from the combined findings dated 2026-10-16. Measurements and test
counts below describe the original run, not a new execution.

## Scope and baseline

The measurements were produced on branch `ale/shared-worker-poc`, based on
local `main` commit `97fac9b`. No code from the large migration experiment was
applied.

The proof covers reading and the existing baseline signing case: one
`c2pa.created` assertion, JPEG, ES256, no timestamp or identity. The direct
signing host generates fixtures and records reference COSE inputs, algorithms,
reports and exclusions. The Worker signing contract uses those same inputs,
but signs with an application-held non-extractable WebCrypto key. No missing
functionality was added to the state machine.

## Findings

- Small and 64 MiB unsigned JPEGs are signed and read back `Trusted`. Algorithms
  and exact COSE signing input bytes match the direct host. Complete read-back
  reports, output/manifest lengths and separate exclusion ranges match too;
  randomized ECDSA signatures need not be byte-identical.
- One large build issues **1,092 reads, 134,217,734 read bytes, 68 writes,
  67,112,416 written bytes, one signature and 268 advances** in all four
  environments. Input is 67,108,864 bytes; output is 67,110,646 bytes.
  Read/write totals include output hashing and placeholder/commit rewrites,
  not just unique source/output bytes.
- The key and callback function never cross the Worker boundary. The same
  application-side WebCrypto signer works unchanged in Node and browsers.
  Snapshot tests cover source bytes, definition and public certificate bytes.
- Delayed signatures leave the build pending while application timer tasks
  progress. Callback replies must bypass the serialized top-level queue:
  otherwise a reply would wait behind the very build awaiting it.
- Replies carry both operation identity and Rust request handle. Queued small
  and large builds mixed with a read return the correct reports; another
  Worker finishes a different build while the first callback remains pending.
- Synchronous throws and async rejections preserve error name/message. Invalid
  reply types/lengths and invalid definitions reject; subsequent builds succeed.
  Original error identity and stack do not survive serialization.
- A 64-byte zero signature passes the transport shape check but reads back
  `Invalid`. Successful building is not signature verification or a trust
  verdict; this remains the signer's responsibility followed by validation.
- Disposal rejects a build without waiting for its signer. Late signature
  success and rejection do not post to the terminated Worker or affect another
  client. The caller-owned signing operation itself is not cancelled.
- Controlled port tests also prove callback transport failures close the client
  and reject its pending operations. Browser harnesses fail on unhandled page
  errors rather than merely logging them.

## Reproduction and limitations

From `js/`, run `npm test` and `npm run test:browser` after the
[build prerequisites](../README.md#run-the-proof). The
[signing contract](../test/signing.mjs) runs in Node and three browsers.
See the [read/lifecycle report](2026-10-16-shared-host-read.md#ownership-and-limitations)
for shared ownership and cancellation limits, and the
[binary transport report](2026-10-16-binary-transport.md#validation-commands)
for the original build and validation checks.

[All experiment reports](README.md)
