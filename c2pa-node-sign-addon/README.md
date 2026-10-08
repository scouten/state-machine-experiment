# c2pa-node-sign-addon

The baseline signing case (see `contentauth-c2pa-sign-baseline`) through
Node, on the same premise as [`c2pa-node-compat-addon`](../c2pa-node-compat-addon)'s
reader: **Node owns every asynchronous operation; Rust holds a state
machine and is only ever called synchronously.** Here the most interesting
asynchronous operation is the signature: the key can live in a KMS, an HSM or
behind WebCrypto, because `signer.sign(data)` is just a function returning a
`Promise`.

```js
import { signAsset } from "./index.mjs";

const result = await signAsset(
  { path: "in.jpg" },
  definition,                       // c2pa-rs-shaped JSON (string or object)
  {
    alg: "es256",
    certs: [certDer],               // DER chain, signer first
    sign: async (data) => kms.sign(data),   // Buffer -> Promise<Buffer>, raw r||s for ECDSA
  },
  { output: { path: "out.jpg" }, concurrency: 4 },
);
// { manifest, exclusions: [{ start, len }, …] }; with no `output`, also `buffer`
```

`new Builder(definition).sign(asset, signer, options)` is the same call.

## The conversation

```js
const session = native.buildNew(definitionJson, format, alg, certs);
for (;;) {
  const step = native.buildAdvance(session);     // sync, one bounded slice of work
  if (step.done) break;
  for (const request of step.requests) {          // read / length / write / sign
    answer(request).then(r => native.buildFulfill(session, request.id, ...r));
  }
  await Promise.race(inFlight);
}
const { manifest, exclusions } = native.buildFinish(session);
```

That is `drive` in `index.mjs`. Streams are `"source"` (read-only) and
`"output"` (written only: the engine hashes the asset as it writes it, for
the hard binding, and never asks to read it back). The Rust side, `contentauth-c2pa-node-compat-sign`,
never buffers either asset and never sees a key.

## Output atomicity

With `output: { path }` the asset is built in a temporary file created
exclusively (`wx+`) under an unpredictable name beside the destination, and
renamed into place only on success; any failure closes and removes it, and an
existing destination is untouched. This mirrors `build_and_sign_file`. Without
`output` the asset is assembled in memory and returned as `buffer`
(the simple version: it reallocates as it grows).

## How this differs from c2pa-node

c2pa-node's signing goes through `CallbackSigner`, which (from my reading
of its design, not something re-verified here) invokes a JavaScript callback
from Rust code running on a tokio worker thread inside c2pa-rs's `Builder`.
Here nothing in Rust waits for JavaScript: the session parks on a `Sign`
request and returns, so no thread is blocked on the signature and the event
loop is simply free. The tests show the observable part of that: a 300 ms
signer while a 5 ms timer keeps ticking, and two signings overlapping on one
thread in about the time of one.

## Timestamps

Give the definition a `tsa_url` or the signer a
`timeAuthorityUrl`, and the claim signature is countersigned with an RFC 3161
timestamp. Rust builds the `TimeStampReq` and unwraps the token from the
response; the session just parks on a `timestamp` request carrying the URL
and the DER request, and Node `POST`s it — with `fetch`, or with
`signer.sendTimestampRequest(url, request)` (a proxy, a client certificate)
if you provide one — and replies with the response body. A refusal or an
unreachable authority fails the build.

## Try it

```sh
npm run build   # cargo build --release, then copies the cdylib to index.node
npm test        # 10 tests under node:test
./coverage.sh   # needs cargo-llvm-cov
```

The tests read results back with the **existing reader addon**
(`../c2pa-node-compat-addon`) and need its `index.node`: `npm test` builds it
if missing (or run `npm run build:reader` first, as CI does). They cover:
the baseline case reading back `Trusted` with the baseline's label, title and
assertions (and not Trusted without the anchor); file and buffer outputs
agreeing; a rejecting signer rejecting the promise with no output and no
temp file left, and an existing output untouched; replacing an existing
output; the event loop ticking during a slow signer; definition, format,
algorithm, missing-file errors; a signer for the wrong algorithm or returning
a non-buffer.

## Limits

* JPEG only; no ingredients or thumbnails (the baseline has
  none); RSASSA-PSS needs a signature length this surface does not yet set.
* Hashing the output runs on the JS thread in small slices, as the reader's
  does. Every request crosses the N-API boundary with a `Buffer` copy.
* A signer that never settles hangs the build; there is no timeout or abort
  option yet. On failure the driver waits for in-flight requests to settle
  before cleaning up.
* Errors: the signer's own error is rethrown as is; engine errors carry the
  Rust-side string as `name` (`Definition(...)`, `C2pa(UnsupportedType)`,
  `Build(...)`).

This directory is its own Cargo workspace (a Neon `cdylib` cannot link under
the root workspace's `--all-features` jobs); CI builds and tests it separately.
