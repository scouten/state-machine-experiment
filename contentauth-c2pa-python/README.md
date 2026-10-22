# contentauth-c2pa-python

Experimental Python bindings over the [canonical C API](../contentauth-c2pa-c-api/),
following the [C++ binding](../contentauth-c2pa-cpp/) architecture. This is a
standalone Python package, not a Cargo workspace member or a C++ wrapper.

## Current scope: phase 4 — asyncio

The compiled CFFI adapter statically links the existing Rust C API and exposes its
two sans-I/O workflows as typed Python sessions, blocking drivers for synchronous access,
and native `asyncio` drivers for everything else. Most callers need only the first two
sections below.

### Reading

```python
import contentauth_c2pa as c2pa

reader = c2pa.read_asset("photo.jpg")          # bytes, a seekable stream, or a path
if reader is None:
    print("no Content Credentials")
else:
    print(reader.validation_state(), reader.json())
```

`read_asset(source, format=None, settings_json=None, *, clock=None, ocsp=None)` returns
`None` for an asset without a manifest store and raises `C2paError` for a malformed one.
A path's own extension is the default `format`; for bytes or a stream you must say what it
is, because the caller, not the library, decides that. The **clock is the host's**:
validation is a function of the asset and the time you supply (the system clock by
default). With no `ocsp` transport, online revocation checks see an unreachable responder,
which the engine treats as fail-open; a transport is `(url, request) -> response`.
Trust anchors go in `settings_json`.

For a live check, pass `ocsp=c2pa.http_ocsp` (or `c2pa.async_http_ocsp` to the asyncio
drivers). Because a responder's URL is chosen by a certificate inside the asset, it only
contacts publicly routable addresses, connects to the address it vetted, and follows no
redirects. See [HTTP transports](#http-transports).

### Signing

```python
import contentauth_c2pa as c2pa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

key = serialization.load_pem_private_key(open("key.pem", "rb").read(), password=None)

def signer(algorithm: str, data: bytes) -> bytes:   # `data` is the COSE Sig_structure
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")   # raw r || s, not DER

report = c2pa.sign_file(
    "in.jpg", "out.jpg",
    definition_json=open("definition.json").read(),
    certificates=[open("signer.der", "rb").read()],        # DER chain, leaf first
    signer=signer,
)
```

`sign_file` publishes **atomically**: the output is built in a freshly and exclusively
created temporary file with an unpredictable name beside the destination, and renamed into
place only after the build succeeds. A failed or interrupted build never changes an
existing destination or leaves debris, and `destination` may equal `source`. The output
takes the source's permission bits, and a symlink destination is replaced rather than
followed. The key never reaches the native library; `timestamper(url, body)` answers an
RFC 3161 request with the complete DER `TimeStampResp`, and a definition requesting a
timestamp fails the build rather than silently omitting it when none is given. When a host
callback fails, the resulting `C2paError` is chained (`__cause__`) to the real exception.
Publication is POSIX-only and does not fsync the containing directory.

### Hosts and drivers

| Surface | Purpose |
|---|---|
| `drive_read(session, host)`, `drive_build(session, host)` | The blocking drivers: answer every request from a host until done. They stop a session that reports no progress; after a failure the session is yours to close (use `with`) |
| `ReadHost` → `BytesReadHost`, `StreamReadHost` | The asset, the clock and OCSP. Subclass for other storage; `read` must return *exactly* the bytes asked for |
| `BuildHost` → `MemoryBuildHost`, `StreamBuildHost`, `FileBuildHost` | Source, output, key and timestamp authority. `StreamBuildHost` needs two distinct seekable streams and an empty output; `FileBuildHost` is the atomic file host |
| `answer_read`, `answer_build` | Answer one request; any `Exception` from the host becomes a `Failed` reply so the engine decides what that means. `KeyboardInterrupt` and `SystemExit` propagate |

## Asyncio

`async_read_asset` and `async_sign_file` take the same arguments as their blocking
counterparts and never block the event loop. A **coroutine-function** `signer`,
`timestamper` or `ocsp` (a remote signing service, say) is awaited on the loop,
concurrently with the file I/O; anything else is called in a worker thread.

```python
import asyncio
import httpx                       # any async HTTP client; not a dependency of this package
import contentauth_c2pa as c2pa

async def remote_signer(algorithm: str, data: bytes) -> bytes:
    # The key never leaves the service. `data` is the COSE Sig_structure; return raw r || s.
    response = await client.post("https://sign.example/es256", content=data)
    response.raise_for_status()
    return response.content

async def main() -> None:
    async with asyncio.timeout(30):                       # bound a slow service
        await c2pa.async_sign_file(
            "in.jpg", "out.jpg",
            definition_json=definition, certificates=[chain], signer=remote_signer,
        )
    reader = await c2pa.async_read_asset("out.jpg")
```

How it works, and what you can rely on:

- **Concurrent, any order.** The session stays synchronous: `advance()` and `fulfill()` are
  brief calls made on the loop. Each request the engine issues becomes its own task, and
  replies are reported as they finish, so a slow request never holds up an independent one.
  Many sessions share one loop and interleave at every request.
- **Cancellation.** Cancelling (or timing out) stops the driver, cancels and awaits every
  in-flight host call, and reports nothing more to the session, which your `with` closes.
  Failures chain to the real exception, as in the blocking drivers.
- **A worker thread cannot be cancelled.** `ThreadReadHost` / `ThreadBuildHost` (the
  adapters behind the helpers above) track every call they start. `close_when_idle()`
  defers releasing a file or temporary output until the last such call has *actually*
  finished, on whichever thread that is, and `wait_idle()` lets you wait for it. So nothing
  is ever closed under a running worker, and a cancelled `async_sign_file` removes its
  temporary output, and closes the files it opened, only after the worker is done with them.
  A cancellation that lands during the final rename may or may not replace the destination,
  but whatever it holds is complete.
- **Thread safety by default.** Blocking-host calls are serialized on one worker thread, so
  hosts that are not thread-safe (stream hosts) are safe. Raise `max_workers` only for
  thread-safe ones such as `FileBuildHost`. `inline=True` runs a host that never blocks (an
  in-memory one) on the loop.

| Surface | Purpose |
|---|---|
| `async_drive_read(session, host)`, `async_drive_build(session, host)` | The asyncio drivers; after a failure the session is yours to close |
| `AsyncReadHost`, `AsyncBuildHost` | Implement these natively (an async file or network client); same contracts as the blocking hosts |
| `ThreadReadHost(host)`, `ThreadBuildHost(host, signer=, timestamper=)` | Serve any blocking host to the loop; `close_when_idle(release)`, `wait_idle()`, `aclose()`, `async with` |

## Low-level sessions

A session never performs I/O: `advance()` reports the requests it needs answered, the
caller services **any subset, in any order**, reports each with `fulfill()`, and
`finish()` consumes the session for its result. The drivers above are built on exactly
this; a host with async, remote or cached access can drive a session directly.

```python
from contentauth_c2pa import (
    Bytes, Length, ReadRequest, LengthRequest, ReadSession, Time, TimeRequest,
)

asset = open("photo.jpg", "rb").read()
with ReadSession("image/jpeg") as session:
    while True:
        step = session.advance()
        for request in step.requests:
            match request:
                case ReadRequest(id=id, start=start, len=n):
                    session.fulfill(id, Bytes(asset[start : start + n]))
                case LengthRequest(id=id):
                    session.fulfill(id, Length(len(asset)))
                case TimeRequest(id=id):
                    session.fulfill(id, Time(1_800_000_000))  # the host owns the clock
        if step.done:
            break
    reader = session.finish()          # None: the asset carries no Content Credentials
    if reader:
        print(reader.validation_state(), reader.json())
```

| Surface | Behavior |
|---|---|
| `ReadSession(format, settings_json=None)` | `advance()`, `fulfill(id, reply)`, `finish() -> Reader \| None`, `close()` |
| `BuildSession(definition_json, format, algorithm, certificates)` | Same lifecycle; `finish() -> SignReport`. The host answers signing and timestamp requests, so no key reaches the native library |
| `Reader` | `json()`, `validation_state()`, `active_label()`, `is_embedded()`, `close()`; everything is copied out of native memory |
| Requests and replies | Frozen dataclasses (`ReadRequest`, `WriteRequest`, `SignRequest`, `Bytes`, `Length`, `Signature`, …) holding owned copies; they stay valid after the session is gone |
| `C2paError` | Carries the native `code` (`ErrorCode`), Debug-style `name` and `message` |

Contracts preserved from the C API:

- An empty batch while `done` is false means *waiting*, not complete.
- A rejected `fulfill` (unknown or already answered id, wrong reply kind) raises
  `C2paError` and leaves the request outstanding and the session usable. An object
  that is not a reply at all raises `TypeError` before reaching native code.
- `finish()` consumes the session whether it succeeds or fails; later use raises
  `ClosedError`. Malformed input raises `C2paError`; only a genuinely unsigned asset
  yields `None`.
- ES256 signatures are raw 64-byte `r || s`, not DER; signing requests carry the full
  COSE `Sig_structure`, not a digest.
- Every native call on a session is serialized by a per-session lock, as the C API
  requires. Sessions may be moved between threads.

Ownership is deterministic: `close()` or a `with` block releases the native handle,
and is safe to repeat. A finalizer is only a safety net for sessions that are dropped.

Not implemented yet: Windows support and production distribution. Lease-backed buffers were measured and deliberately not
built; see [Copies and leases](#copies-and-leases). `native_version()` returns the linked
native library version.

## HTTP transports

`http_ocsp(url, request)` and `http_timestamper(url, request)` are standard-library
callbacks (no new dependency) with `async_` forms that run on a worker thread. Both are
opt-in: with none given, an OCSP check sees an unreachable responder and a requested
timestamp fails the build, as before. Both bound the response (1 MiB) and each connect and
read (30 s), accept only `http`/`https` URLs without credentials, and follow no redirects;
a failure raises (`HttpError` for a bad status or oversize body, `OSError` for the network)
and the engine's fail-open OCSP handling does the rest.

They differ in how far the URL is trusted. A timestamp authority's comes from the signing
party. An OCSP responder's comes from a certificate in the asset being read, so
`http_ocsp` refuses a host unless **every** address it resolves to is globally routable
(no loopback, private, link-local, cloud-metadata or multicast, IPv4-mapped forms
included), then connects to that vetted address rather than resolving again, so a second
DNS answer cannot redirect it; TLS still verifies the certificate against the URL's name.
A call already running on a worker thread when its task is cancelled finishes or times
out, but nothing is delivered to the session afterwards. The timestamp transport is only
tested against a loopback server, not a real authority.

## Copies and leases

Replies and write payloads are **copied** across the boundary: the engine copies a reply
before `fulfill()` returns, and a write request is copied into a Python `bytes`. The C API
can instead lend storage ("leases"): `preadv` straight into engine-owned memory for a read,
`pwrite` straight from engine-owned memory for a write, as the C++ binding does. Whether
that is worth its cost was measured rather than assumed, with
[`benchmarks/copy_cost.py`](benchmarks/copy_cost.py), which signs a large file with the
shipped driver and with hand-written raw-C-API loops, interleaved and shuffled each round.
On one Apple-silicon laptop, warm page cache, median of 25 rounds:

| Signing a… | shipped driver | raw loop, no leases (control) | read leases | write leases | both |
|---|---|---|---|---|---|
| 134 MB file | 123.7 ms (+5.9%) | 116.8 ms | 108.4 ms (−7.2%) | 112.9 ms (−3.3%) | 105.4 ms (−9.7%) |
| 17 MB file | 16.2 ms (+4.0%) | 15.6 ms | 14.1 ms (−9.7%) | 15.1 ms (−2.9%) | 13.9 ms (−10.9%) |

What the numbers say:

- Throughput is about 1 GB/s. Where the time goes (profiling `sign_file`): roughly half is
  the kernel's `pwrite`, a quarter the engine's hashing, and the copies a small remainder.
  A memcpy of the whole asset costs about 8 ms against ~120 ms for the build.
- **Write leases buy almost nothing** (≈3%): the cost is the kernel write, not the copy.
- **Read leases buy about 7–10%** on signing. Reading has no lease API at all, so
  `read_asset` gains nothing, and an async or network host is dominated by its own latency.
- The Python driver itself costs about 4–6% over a raw loop, which is what you pay for typed
  requests, per-session locking and error mapping.

So leases were **not built**. A gain of under a tenth, on one workload, does not justify the
extra public surface: a writable view onto engine memory is only safe if the library can
prove no reference outlives the seal that hands the storage back (`memoryview.release()` can
supply that proof, but every host, the async driver and the thread adapters would have to
honour it), and a cancelled worker thread could be mid-`preadv` into a lease while its
session is gone. This is the kind of optimisation to revisit if a workload shows copies
mattering, not before. One cheap improvement did come out of the measurement: the stream
and file hosts used to copy every read a second time while gathering it, and now return a
complete read as it is.

## Next phases

CI's `python-binding` job (Ubuntu and macOS, Python 3.11 and 3.13) builds the wheel from a
checkout, installs it into a clean virtual environment, and runs the suite against the
*installed* wheel with the 100% coverage floor and `mypy --strict`. It certifies that the
wheel builds and works on those runners; it is not a published-wheel matrix.

The `Python wheels` workflow (`.github/workflows/python-wheels.yml`, run by hand, on a
`python-v*` tag, or when packaging files change) builds wheels with `cibuildwheel` for
CPython 3.11–3.13 on manylinux_2_28 and musllinux_1_2 (x86_64 and aarch64, on native
runners) and macOS (arm64 and Intel), and runs the whole suite against each installed
wheel in its own build environment. It uploads the wheels as workflow artifacts and
**publishes nothing**. The Linux aarch64 manylinux and musllinux builds were also run
locally under Docker, with all tests passing; the x86_64 and macOS legs have not been run.

Remaining: publication (where, and under what name and versioning, is undecided), Windows
(the file hosts use POSIX calls such as `os.pread`), cross-compilation, and a real-asset
corpus compared against c2pa-rs.

### Known engine behavior

The engine accepts a `TimestampResponse` reply to a *length* request and then fails the
whole build on the next `advance()`, instead of rejecting the reply and leaving the
request outstanding as it does for other mismatched kinds. This is existing
engine/C-ABI behavior, not changed or masked here.

## Build and install

Requires Python 3.11 or newer, Cargo/Rust meeting the workspace's MSRV, and a C
compiler with Python development headers. Initial build support is macOS and
Linux on the build machine's native architecture; Windows and cross-compilation
are not supported yet. The wheel workflow above builds wheels for Linux and macOS but has not
yet been run on GitHub.

From the **repository root**, using [uv](https://docs.astral.sh/uv/):

```sh
uv venv contentauth-c2pa-python/.venv
uv build --python contentauth-c2pa-python/.venv/bin/python \
  --wheel contentauth-c2pa-python --out-dir contentauth-c2pa-python/dist
uv pip install --python contentauth-c2pa-python/.venv/bin/python \
  --find-links contentauth-c2pa-python/dist contentauth-c2pa-python
contentauth-c2pa-python/.venv/bin/python -c \
  'from contentauth_c2pa import native_version; print(native_version())'
```

The build compiles `contentauth-c2pa-c-api` in release mode, with its default
read/build features, into this package's ignored `build/cargo` directory.
The CFFI declarations are derived directly from the generated C header (every
declaration the adapter uses is required to be present exactly once), not maintained
as a second handwritten ABI. The compiler checks them against that header. No Rust
source changes or shared-library conversion are required.

Build wheels from a full repository checkout. Standalone source distributions
are deliberately rejected until they can include the required workspace
sources. Installing a built wheel requires neither Cargo, a compiler, nor a
separately installed C API library; CFFI remains a Python runtime dependency.
Cargo and the Python build frontend may download their declared dependencies.

## Validation

Install the wheel and development dependencies into the virtual environment,
then run from this directory:

```sh
uv pip install --python .venv/bin/python \
  --find-links dist 'contentauth-c2pa-python[dev]'
.venv/bin/python -m pytest --cov --cov-report=term-missing
.venv/bin/python -m mypy
```

Tests drive real sessions against the compiled library with in-memory hosts:
reading a signed, unsigned and malformed JPEG; signing a JPEG with a caller-owned
ES256 key and reading it back `Trusted` (and only `Valid` without the anchor, or
with a clock before the signer's validity); out-of-order, late and partial replies;
rejected replies; failed signing, writing and timestamping; early finish, reuse
after finish, repeated close and finalizer cleanup; and threaded use. Native
request kinds that cannot be provoked offline (OCSP, timestamp) are exercised
through synthetic descriptors, and the Python enums are checked against the header's
constants so they cannot drift. Host and driver tests cover each host's bounds,
short-read and partial-write handling; descriptor and temporary-file hygiene when a
build fails, is interrupted, or cannot publish; a signed asset being byte-identical
across the memory, stream and file hosts; host-failure chaining; stalled sessions; and
concurrent file signing. TIFF (little- and big-endian, classic and BigTIFF) is exercised end to end: unsigned, signed
and read back `Trusted`, tampered, identical across the memory, stream and file hosts, and
chosen by a path's extension. Asyncio tests (no `pytest-asyncio`: each runs on a fresh loop that
fails the test on any stray task or unretrieved exception) check parity with the blocking
drivers, concurrent in-flight requests, out-of-order completion, two sessions interleaving
on one loop, and cancellation at *every* request kind, including while a worker thread is
mid-write, mid-signature, mid-read or mid-rename, with the invariant that nothing is closed
or removed under a running worker and nothing is delivered to a closed session. Those tests
were mutation-checked: disabling the deferred release or the in-flight cancellation makes
them fail. The wheel/import tests still import from outside the
checkout in isolated Python mode with an empty executable search path (no Cargo or
compiler available). Build-helper tests cover header extraction, platform selection,
Cargo invocation/failure propagation, and rejection of unsupported source
distributions. Test-only dependency: `cryptography`, as the example signer.
