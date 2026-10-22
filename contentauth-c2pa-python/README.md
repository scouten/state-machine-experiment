# contentauth-c2pa-python

Experimental Python bindings over the [canonical C API](../contentauth-c2pa-c-api/),
following the [C++ binding](../contentauth-c2pa-cpp/) architecture. This is a
standalone Python package, not a Cargo workspace member or a C++ wrapper.

## Current scope: phase 3 — blocking hosts and file signing

The compiled CFFI adapter statically links the existing Rust C API and exposes its
two sans-I/O workflows as typed Python sessions, plus blocking drivers for the common
case of synchronous access. Most callers need only the first two functions below.

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

Not implemented yet: asyncio, lease-backed zero-copy buffers (replies and write
payloads are copied), Windows support, an HTTP transport for OCSP or timestamps (callbacks
only) and production distribution. They remain separate, approval-gated phases.
`native_version()` returns the linked native library version.

### Known engine behavior

The engine accepts a `TimestampResponse` reply to a *length* request and then fails the
whole build on the next `advance()`, instead of rejecting the reply and leaving the
request outstanding as it does for other mismatched kinds. This is existing
engine/C-ABI behavior, not changed or masked here.

## Build and install

Requires Python 3.11 or newer, Cargo/Rust meeting the workspace's MSRV, and a C
compiler with Python development headers. Initial build support is macOS and
Linux on the build machine's native architecture; Windows and cross-compilation
are not supported yet. A supported-platform wheel matrix is not yet certified.

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
concurrent file signing. The wheel/import tests still import from outside the
checkout in isolated Python mode with an empty executable search path (no Cargo or
compiler available). Build-helper tests cover header extraction, platform selection,
Cargo invocation/failure propagation, and rejection of unsupported source
distributions. Test-only dependency: `cryptography`, as the example signer.

## Next phases

4. Native asyncio drivers and cancellation-safe host operations.
5. Lease-backed buffer optimizations and measurements.
6. Broader integration coverage, CI and distributable wheel certification.
