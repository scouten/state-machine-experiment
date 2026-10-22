import importlib.util
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from unittest.mock import Mock

import pytest
import setuptools
from setuptools.command.build_ext import build_ext
from setuptools.dist import Distribution
from setuptools.errors import SetupError


@pytest.fixture
def package_setup(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    registration = Mock()
    monkeypatch.setattr(setuptools, "setup", registration)
    path = Path(__file__).resolve().parents[1] / "setup.py"
    spec = importlib.util.spec_from_file_location("_package_setup", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    registration.assert_called_once_with(
        cffi_modules=["_build.py:ffibuilder"],
        cmdclass={"build_ext": module.NativeBuild, "sdist": module.CheckoutOnlySdist},
    )
    return module


def test_cargo_build_precedes_extension_build(
    package_setup: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = Mock()
    monkeypatch.setattr(package_setup.subprocess, "run", calls.cargo)
    monkeypatch.setattr(build_ext, "run", calls.extension)

    package_setup.NativeBuild(Distribution()).run()

    assert calls.mock_calls[0].args == (
        [
            "cargo",
            "build",
            "--manifest-path",
            str(package_setup.WORKSPACE_ROOT / "Cargo.toml"),
            "--package",
            "contentauth-c2pa-c-api",
            "--release",
            "--target-dir",
            str(package_setup.PACKAGE_ROOT / "build" / "cargo"),
        ],
    )
    assert calls.mock_calls[0].kwargs == {
        "cwd": package_setup.WORKSPACE_ROOT,
        "check": True,
    }
    assert [call[0] for call in calls.mock_calls] == ["cargo", "extension"]


def test_native_build_requires_workspace(
    package_setup: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(package_setup, "WORKSPACE_ROOT", tmp_path)
    with pytest.raises(SetupError, match="full repository checkout"):
        package_setup.NativeBuild(Distribution()).run()


def test_cargo_failure_stops_extension_build(
    package_setup: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    cargo = Mock(side_effect=subprocess.CalledProcessError(1, ["cargo", "build"]))
    extension = Mock()
    monkeypatch.setattr(package_setup.subprocess, "run", cargo)
    monkeypatch.setattr(build_ext, "run", extension)

    with pytest.raises(subprocess.CalledProcessError):
        package_setup.NativeBuild(Distribution()).run()
    extension.assert_not_called()


def test_source_distribution_is_rejected(package_setup: ModuleType) -> None:
    with pytest.raises(SetupError, match="Source distributions are not supported"):
        package_setup.CheckoutOnlySdist(Distribution()).run()
