"""Build the CFFI extension against the workspace's canonical C API."""

from pathlib import Path
import subprocess

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.command.sdist import sdist
from setuptools.errors import SetupError


PACKAGE_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = PACKAGE_ROOT.parent


class NativeBuild(build_ext):
    def run(self) -> None:
        manifest = WORKSPACE_ROOT / "Cargo.toml"
        if not manifest.is_file():
            raise SetupError("Build the Python wheel from a full repository checkout.")
        subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(manifest),
                "--package",
                "contentauth-c2pa-c-api",
                "--release",
                "--target-dir",
                str(PACKAGE_ROOT / "build" / "cargo"),
            ],
            cwd=WORKSPACE_ROOT,
            check=True,
        )
        super().run()


class CheckoutOnlySdist(sdist):
    def run(self) -> None:
        raise SetupError(
            "Source distributions are not supported yet. "
            "Build a wheel from the full repository checkout instead."
        )


setup(
    cffi_modules=["_build.py:ffibuilder"],
    cmdclass={"build_ext": NativeBuild, "sdist": CheckoutOnlySdist},
)
