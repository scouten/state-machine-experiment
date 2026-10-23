"""Derive the CFFI declarations from the canonical generated header."""

from pathlib import Path
import re
import sys

from cffi import FFI


PACKAGE_ROOT = Path(__file__).resolve().parent
API_ROOT = PACKAGE_ROOT.parent / "contentauth-c2pa-c-api"


REQUIRED_FUNCTIONS = (
    "c2pa_sm_version",
    "c2pa_sm_string_free",
    "c2pa_sm_error_code",
    "c2pa_sm_error_message",
    "c2pa_sm_error_name",
    "c2pa_sm_error_free",
    "c2pa_sm_session_new",
    "c2pa_sm_session_free",
    "c2pa_sm_session_advance",
    "c2pa_sm_session_request_count",
    "c2pa_sm_session_request",
    "c2pa_sm_session_fulfill",
    "c2pa_sm_session_finish",
    "c2pa_sm_reader_free",
    "c2pa_sm_reader_json",
    "c2pa_sm_reader_validation_state",
    "c2pa_sm_reader_active_label",
    "c2pa_sm_reader_is_embedded",
    "c2pa_sm_build_session_new",
    "c2pa_sm_build_session_advance",
    "c2pa_sm_build_session_request",
    "c2pa_sm_build_session_fulfill",
    "c2pa_sm_build_session_finish",
    "c2pa_sm_build_session_free",
    "c2pa_sm_sign_report_view",
    "c2pa_sm_sign_report_free",
)


def cdef_from_header(header: str) -> str:
    """Turn the generated C header into CFFI declarations, without a second ABI copy."""
    uncommented = re.sub(r"/\*.*?\*/|//[^\n]*", "", header, flags=re.DOTALL)
    kept = []
    for line in uncommented.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            # CFFI understands only integer constants among the header's directives.
            if re.fullmatch(r"#define\s+C2PA_SM_\w+\s+-?\d+", stripped):
                kept.append(stripped)
            continue
        # The only lone brace is the end of the C++ `extern "C"` guard.
        if stripped in ('extern "C" {', "}"):
            continue
        kept.append(line)
    declarations = "\n".join(kept)
    problems = [
        name
        for name in REQUIRED_FUNCTIONS
        if len(re.findall(rf"\b{name}\s*\(", declarations)) != 1
    ]
    if problems:
        raise ValueError(
            "Expected exactly one declaration of each required function in the C API "
            f"header; check: {', '.join(problems)}."
        )
    return declarations


def native_libraries(platform: str) -> list[str]:
    """Select the native dependencies for the initial POSIX builds."""
    if platform == "darwin":
        return ["pthread", "m"]
    if platform == "linux":
        return ["dl", "pthread", "m"]
    raise ValueError(f"Python native builds currently support macOS and Linux, not {platform!r}.")


ffibuilder = FFI()
ffibuilder.cdef(
    cdef_from_header(
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
