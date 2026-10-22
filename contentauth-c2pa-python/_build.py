"""Select CFFI declarations from the canonical generated header."""

from pathlib import Path
import re
import sys

from cffi import FFI


PACKAGE_ROOT = Path(__file__).resolve().parent
API_ROOT = PACKAGE_ROOT.parent / "contentauth-c2pa-c-api"


def version_declaration(header: str) -> str:
    """Read the native signature without maintaining a second ABI declaration."""
    uncommented = re.sub(r"/\*.*?\*/|//[^\n]*", "", header, flags=re.DOTALL)
    matches = re.findall(
        r"^[^\n;{}]*\bc2pa_sm_version\s*\([^;{}]*\)\s*;",
        uncommented,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError("Expected exactly one c2pa_sm_version declaration in the C API header.")
    return matches[0].strip()


def native_libraries(platform: str) -> list[str]:
    """Select the native dependencies for the initial POSIX builds."""
    if platform == "darwin":
        return ["pthread", "m"]
    if platform == "linux":
        return ["dl", "pthread", "m"]
    raise ValueError(f"Python native builds currently support macOS and Linux, not {platform!r}.")


ffibuilder = FFI()
ffibuilder.cdef(
    version_declaration(
        (API_ROOT / "include" / "contentauth_c2pa_c_api.h").read_text(encoding="utf-8")
    )
)
ffibuilder.set_source(
    "contentauth_c2pa._native",
    '#include "contentauth_c2pa_c_api.h"',
    include_dirs=[str(API_ROOT / "include")],
    extra_objects=[
        str(PACKAGE_ROOT / "build" / "cargo" / "release" / "libcontentauth_c2pa_c_api.a")
    ],
    libraries=native_libraries(sys.platform),
)
