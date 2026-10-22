"""Experimental Python adapter for the canonical C2PA session C API."""

from ._native import ffi as _ffi, lib as _lib

__all__ = ["native_version"]


def native_version() -> str:
    """Return the linked native library's version, not the Python package version."""
    return _ffi.string(_lib.c2pa_sm_version()).decode("utf-8")
