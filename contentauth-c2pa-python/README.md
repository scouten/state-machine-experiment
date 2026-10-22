# contentauth-c2pa-python

Experimental Python bindings over the [canonical C API](../contentauth-c2pa-c-api/),
following the [C++ binding](../contentauth-c2pa-cpp/) architecture. This is a
standalone Python package, not a Cargo workspace member or a C++ wrapper.

## Current scope: phase 1

The compiled CFFI adapter statically links the existing Rust C API. Its only
public function is currently:

```python
from contentauth_c2pa import native_version

print(native_version())
```

The function returns the linked native library version. Python does not free
that static native string. Native imports and decoding errors propagate;
there is no fallback to a Python-only implementation.

Session APIs, reading, signing, host I/O, asyncio, buffer leases and production
distribution are not implemented. They remain separate, approval-gated phases.
The Python package includes typing information for its current public surface.

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
The CFFI function declaration is selected directly from the generated C header,
not maintained as a second handwritten ABI. The compiler checks it against that
header. No Rust source changes or shared-library conversion are required.

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

Tests exercise the compiled native call, compare its version to the C API's
manifest, check wheel metadata and typing files, and import from outside the
checkout in isolated Python mode with an empty executable search path (no
Cargo or compiler available). Build-helper tests cover header declaration
selection, platform selection, Cargo invocation/failure propagation, and explicit
rejection of unsupported source distributions.

## Next phases

2. Typed low-level read/build sessions and deterministic ownership.
3. Blocking reading/signing hosts, including atomic file output.
4. Native asyncio drivers and cancellation-safe host operations.
5. Lease-backed buffer optimizations and measurements.
6. Broader integration coverage, CI and distributable wheel certification.
