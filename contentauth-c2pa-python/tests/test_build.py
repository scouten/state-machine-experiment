import importlib.util
from pathlib import Path
import sys
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def builder() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "_build.py"
    spec = importlib.util.spec_from_file_location("_build", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "declaration",
    [
        "const char *c2pa_sm_version(void);",
        "const char * c2pa_sm_version (\nvoid\n);",
    ],
)
def test_declaration_is_read_from_header(builder: ModuleType, declaration: str) -> None:
    header = f'#include <stdint.h>\nextern "C" {{\n{declaration}\n}}\n'
    assert builder.version_declaration(header) == declaration


def test_comments_are_not_declarations(builder: ModuleType) -> None:
    declaration = "const char *c2pa_sm_version(void);"
    header = f"/* {declaration} */\n// {declaration}\n{declaration}"
    assert builder.version_declaration(header) == declaration


@pytest.mark.parametrize(
    "header",
    [
        "",
        "/* const char *c2pa_sm_version(void); */",
        "const char *c2pa_sm_version_extra(void);",
        "const char *c2pa_sm_version(void);\nconst char *c2pa_sm_version(void);",
    ],
)
def test_missing_or_duplicate_declaration_fails_explicitly(
    builder: ModuleType, header: str
) -> None:
    with pytest.raises(ValueError, match="Expected exactly one"):
        builder.version_declaration(header)


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
