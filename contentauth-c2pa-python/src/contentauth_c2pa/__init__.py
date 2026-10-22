"""Experimental Python adapter for the canonical C2PA session C API.

A session is a synchronous state machine: `advance()` reports the requests it needs
answered, the caller services any subset of them and reports back with `fulfill()`,
and `finish()` consumes the session for its result. Sessions never perform I/O.
"""

from ._native import ffi as _ffi, lib as _lib
from .build import BuildSession
from .errors import C2paError, ClosedError, ErrorCode
from .read import Reader, ReadSession, ValidationState
from .vocab import (
    Buffer,
    BuildLengthRequest,
    BuildReadRequest,
    BuildReply,
    BuildRequest,
    BuildStep,
    BuildStream,
    Bytes,
    Exclusion,
    Failed,
    Length,
    LengthRequest,
    Ocsp,
    OcspRequest,
    ReadRequest,
    Reply,
    Request,
    Signature,
    SignReport,
    SignRequest,
    Step,
    Time,
    TimeRequest,
    TimestampRequest,
    TimestampResponse,
    Written,
    WriteRequest,
)

__all__ = [
    "Buffer",
    "BuildLengthRequest",
    "BuildReadRequest",
    "BuildReply",
    "BuildRequest",
    "BuildSession",
    "BuildStep",
    "BuildStream",
    "Bytes",
    "C2paError",
    "ClosedError",
    "ErrorCode",
    "Exclusion",
    "Failed",
    "Length",
    "LengthRequest",
    "Ocsp",
    "OcspRequest",
    "ReadRequest",
    "ReadSession",
    "Reader",
    "Reply",
    "Request",
    "SignReport",
    "SignRequest",
    "Signature",
    "Step",
    "Time",
    "TimeRequest",
    "TimestampRequest",
    "TimestampResponse",
    "ValidationState",
    "WriteRequest",
    "Written",
    "native_version",
]


def native_version() -> str:
    """Return the linked native library's version, not the Python package version."""
    return str(_ffi.string(_lib.c2pa_sm_version()).decode("utf-8"))
