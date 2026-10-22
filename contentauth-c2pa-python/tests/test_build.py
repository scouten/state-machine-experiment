import importlib.util
from pathlib import Path
import sys
from types import ModuleType

from cffi import FFI
import pytest

HEADER = (
    Path(__file__).resolve().parents[2]
    / "contentauth-c2pa-c-api"
    / "include"
    / "contentauth_c2pa_c_api.h"
)


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "_build.py"
    spec = importlib.util.spec_from_file_location("_build", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def declarations(builder: ModuleType, *, omit: str = "", repeat: str = "") -> str:
    lines = [f"int {name}(void);" for name in builder.REQUIRED_FUNCTIONS if name != omit]
    if repeat:
        lines.append(f"int {repeat}(void);")
    return "\n".join(lines)


def test_real_header_yields_parseable_declarations(builder: ModuleType) -> None:
    cdef = builder.cdef_from_header(HEADER.read_text(encoding="utf-8"))
    FFI().cdef(cdef)
    assert "#include" not in cdef and "extern" not in cdef and "/*" not in cdef
    assert "#define C2PA_SM_OK 0" in cdef


def test_only_integer_constants_survive_preprocessing(builder: ModuleType) -> None:
    header = (
        "#ifndef GUARD_H\n#define GUARD_H\n#define C2PA_SM_NEG -1\n"
        '#define C2PA_SM_TEXT "text"\n#ifdef __cplusplus\nextern "C" {\n#endif\n'
        f"{declarations(builder)}\n#ifdef __cplusplus\n}}\n#endif\n#endif\n"
    )
    cdef = builder.cdef_from_header(header)
    assert "#define C2PA_SM_NEG -1" in cdef
    assert "GUARD_H" not in cdef and "TEXT" not in cdef and "extern" not in cdef
    assert not any(line.strip() == "}" for line in cdef.splitlines())


def test_comments_are_not_declarations(builder: ModuleType) -> None:
    header = f"/* int {builder.REQUIRED_FUNCTIONS[0]}(void); */\n{declarations(builder)}"
    assert builder.cdef_from_header(header).count(builder.REQUIRED_FUNCTIONS[0]) == 1


@pytest.mark.parametrize("problem", ["missing", "duplicate", "commented"])
def test_missing_or_duplicate_function_fails_explicitly(
    builder: ModuleType, problem: str
) -> None:
    name = builder.REQUIRED_FUNCTIONS[3]
    header = {
        "missing": declarations(builder, omit=name),
        "duplicate": declarations(builder, repeat=name),
        "commented": f"/*\n{declarations(builder)}\n*/",
    }[problem]
    with pytest.raises(ValueError, match="Expected exactly one declaration"):
        builder.cdef_from_header(header)


@pytest.mark.parametrize(
    ("platform", "expected"),
    [("darwin", ["pthread", "m"]), ("linux", ["dl", "pthread", "m"])],
)
def test_platform_link_libraries(
    builder: ModuleType, platform: str, expected: list[str]
) -> None:
    assert builder.native_libraries(platform) == expected


def test_unsupported_platform_fails_explicitly(builder: ModuleType) -> None:
    with pytest.raises(ValueError, match="not 'win32'"):
        builder.native_libraries("win32")
