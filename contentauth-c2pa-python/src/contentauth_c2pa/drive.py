"""Blocking drivers: run a session to completion against a host, one request at a time."""

from collections.abc import Sequence
import os
from pathlib import Path
from typing import BinaryIO

from .build import BuildSession
from .errors import C2paError, ErrorCode
from .hosts import (
    BuildHost,
    BytesReadHost,
    Clock,
    FileBuildHost,
    OcspTransport,
    ReadHost,
    Signer,
    StreamReadHost,
    Timestamper,
)
from .read import Reader, ReadSession
from .vocab import (
    Buffer,
    BuildLengthRequest,
    BuildReadRequest,
    BuildReply,
    BuildRequest,
    Bytes,
    Failed,
    Length,
    LengthRequest,
    Ocsp,
    ReadRequest,
    Reply,
    Request,
    Signature,
    SignReport,
    SignRequest,
    Time,
    TimeRequest,
    TimestampResponse,
    Written,
    WriteRequest,
)

ReadSource = bytes | bytearray | memoryview | BinaryIO | str | os.PathLike[str]


def _exact(data: Buffer, length: int) -> Buffer:
    """A host must never acknowledge a short (or long) read."""
    size = memoryview(data).nbytes
    if size != length:
        raise ValueError(f"the host returned {size} bytes for a read of {length}")
    return data


def _failed(error: Exception) -> Failed:
    return Failed(str(error) or type(error).__name__)


def _read_reply(host: ReadHost, request: Request) -> Reply:
    if isinstance(request, ReadRequest):
        return Bytes(_exact(host.read(request.start, request.len), request.len))
    if isinstance(request, LengthRequest):
        return Length(host.length())
    if isinstance(request, TimeRequest):
        return Time(host.now())
    return Ocsp(host.ocsp(request.url, request.body))


def _build_reply(host: BuildHost, request: BuildRequest) -> BuildReply:
    if isinstance(request, BuildReadRequest):
        data = host.read(request.stream, request.start, request.len)
        return Bytes(_exact(data, request.len))
    if isinstance(request, BuildLengthRequest):
        return Length(host.length(request.stream))
    if isinstance(request, WriteRequest):
        host.write(request.stream, request.offset, request.data)
        return Written()
    if isinstance(request, SignRequest):
        return Signature(host.sign(request.algorithm, request.data))
    return TimestampResponse(host.timestamp(request.url, request.body))


def answer_read(host: ReadHost, request: Request) -> Reply:
    """Answer one read request from `host`; an exception becomes a `Failed` reply."""
    try:
        return _read_reply(host, request)
    except Exception as error:
        return _failed(error)


def answer_build(host: BuildHost, request: BuildRequest) -> BuildReply:
    """Answer one build request from `host`; an exception becomes a `Failed` reply."""
    try:
        return _build_reply(host, request)
    except Exception as error:
        return _failed(error)


def _stalled() -> C2paError:
    return C2paError(
        ErrorCode.INVALID_ARGUMENT,
        "SessionStalled",
        "the session is not done but reported no new requests after all were answered",
    )


def drive_read(session: ReadSession, host: ReadHost) -> Reader | None:
    """Run `session` to completion, answering every request from `host`.

    Returns `None` for an asset without Content Credentials. The session is consumed on
    success; after a failure it is the caller's to close (use it in a `with` block).
    """
    while True:
        step = session.advance()
        if step.done:
            return session.finish()
        if not step.requests:
            raise _stalled()
        for request in step.requests:
            session.fulfill(request.id, answer_read(host, request))


def drive_build(session: BuildSession, host: BuildHost) -> SignReport:
    """Run `session` to completion, answering every request from `host`.

    Any host failure fails the build. The `C2paError` that results is chained to the
    host exception that caused it, so its traceback names the real problem. The session
    is consumed on success; after a failure it is the caller's to close.
    """
    cause: Exception | None = None
    try:
        while True:
            step = session.advance()
            if step.done:
                return session.finish()
            if not step.requests:
                raise _stalled()
            for request in step.requests:
                try:
                    reply = _build_reply(host, request)
                except Exception as error:
                    cause = error
                    reply = _failed(error)
                session.fulfill(request.id, reply)
    except C2paError as error:
        if cause is None:
            raise
        raise error from cause


def _format_of(path: str | os.PathLike[str], format: str | None) -> str:
    if format is not None:
        return format
    suffix = Path(path).suffix.lstrip(".")
    if not suffix:
        raise ValueError(f"cannot infer the asset format from {os.fspath(path)!r}; pass format=")
    return suffix


def read_asset(
    source: ReadSource,
    format: str | None = None,
    settings_json: str | None = None,
    *,
    clock: Clock | None = None,
    ocsp: OcspTransport | None = None,
) -> Reader | None:
    """Read and validate the Content Credentials of an asset.

    `source` is the asset's bytes, a seekable binary stream (left open), or a file path.
    `format` is a MIME type or extension; a path's own extension is the default, since the
    caller, not this function, decides what an asset is. `clock` supplies Unix seconds (the
    system clock by default) and `ocsp` an OCSP transport; without one, online revocation
    checks see an unreachable responder, which the engine treats as fail-open.

    Returns `None` when the asset carries no manifest store, and raises `C2paError` when it
    is malformed or cannot be validated.
    """
    if isinstance(source, str | os.PathLike):
        with open(source, "rb") as stream, ReadSession(
            _format_of(source, format), settings_json
        ) as session:
            return drive_read(session, StreamReadHost(stream, clock=clock, ocsp=ocsp))
    if format is None:
        raise ValueError("format is required when the source is not a file path")
    host: ReadHost
    if isinstance(source, bytes | bytearray | memoryview):
        host = BytesReadHost(source, clock=clock, ocsp=ocsp)
    else:
        host = StreamReadHost(source, clock=clock, ocsp=ocsp)
    with ReadSession(format, settings_json) as session:
        return drive_read(session, host)


def sign_file(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    definition_json: str,
    certificates: Sequence[Buffer],
    signer: Signer,
    algorithm: str = "es256",
    format: str | None = None,
    timestamper: Timestamper | None = None,
) -> SignReport:
    """Sign the file `source` into `destination`, publishing the result atomically.

    The key stays with the caller: `signer(algorithm, data)` receives the complete COSE
    `Sig_structure` (not a digest) and returns the signature, which for ES256 is raw
    64-byte `r || s`, not DER. `timestamper(url, body)` answers an RFC 3161 request with the
    complete DER `TimeStampResp`; without one, a definition requesting a timestamp fails
    the build rather than silently producing an untimestamped manifest.

    A failed build never changes an existing `destination` or leaves debris beside it.
    `destination` may equal `source`, in which case the original is replaced atomically.
    """
    with BuildSession(
        definition_json, _format_of(source, format), algorithm, certificates
    ) as session, FileBuildHost(
        source, destination, signer=signer, timestamper=timestamper
    ) as host:
        report = drive_build(session, host)
        host.publish()
    return report
