from importlib import metadata, resources
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
import subprocess
import sys
import tomllib

import contentauth_c2pa
from contentauth_c2pa import _native, native_version


def test_version_comes_from_native_library() -> None:
    manifest = Path(__file__).resolve().parents[2] / "contentauth-c2pa-c-api" / "Cargo.toml"
    expected = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["version"]
    assert native_version() == expected


def test_package_has_distribution_metadata() -> None:
    assert metadata.version("contentauth-c2pa-python") == "0.1.0"
    assert contentauth_c2pa.__all__ == ["native_version"]


def test_native_module_is_a_compiled_extension() -> None:
    assert any(_native.__file__.endswith(suffix) for suffix in EXTENSION_SUFFIXES)


def test_wheel_includes_typing_information() -> None:
    package = resources.files(contentauth_c2pa)
    assert package.joinpath("py.typed").is_file()
    assert package.joinpath("_native.pyi").is_file()


def test_installed_package_works_outside_checkout(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "from contentauth_c2pa import native_version; print(native_version())",
        ],
        cwd=tmp_path,
        env={"PATH": ""},
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == native_version()


def test_static_native_string_can_be_read_repeatedly() -> None:
    expected = native_version()
    assert all(native_version() == expected for _ in range(1000))
