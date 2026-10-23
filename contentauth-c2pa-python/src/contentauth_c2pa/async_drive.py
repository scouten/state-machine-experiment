"""Asyncio drivers: run a session while its hosts await, never blocking the event loop.

The session stays synchronous: `advance()` and `fulfill()` are brief calls made on the
event loop between awaits. Every request the engine issues becomes its own task, answered
concurrently and reported as each finishes, in any order, so a slow request never holds up
an independent one, and several sessions share one loop, interleaving at every request.

If the driver is cancelled, its in-flight host tasks are cancelled and awaited, and
nothing is reported to the session afterwards (the caller's `with` closes it). Operations
a worker thread has already started cannot be revoked; the thread adapters in
`async_hosts` keep their resources alive until those finish.
"""

import asyncio
from collections.abc import Callable, Coroutine, Sequence
import os
from typing import Any

from .async_hosts import (
    AsyncBuildHost,
    AsyncOcspTransport,
    AsyncReadHost,
    AsyncSigner,
    AsyncTimestamper,
    ThreadBuildHost,
    ThreadReadHost,
    is_coroutine_function,
)
from .build import BuildSession
from .drive import ReadSource, _exact, _failed, _format_of, _stalled
from .errors import C2paError
from .hosts import (
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

_Outcome = tuple[Any, Exception | None]


async def _read_reply(host: AsyncReadHost, request: Request) -> Reply:
    if isinstance(request, ReadRequest):
        return Bytes(_exact(await host.read(request.start, request.len), request.len))
    if isinstance(request, LengthRequest):
        return Length(await host.length())
    if isinstance(request, TimeRequest):
        return Time(await host.now())
    return Ocsp(await host.ocsp(request.url, request.body))


async def _build_reply(host: AsyncBuildHost, request: BuildRequest) -> BuildReply:
    if isinstance(request, BuildReadRequest):
        data = await host.read(request.stream, request.start, request.len)
        return Bytes(_exact(data, request.len))
    if isinstance(request, BuildLengthRequest):
        return Length(await host.length(request.stream))
    if isinstance(request, WriteRequest):
        await host.write(request.stream, request.offset, request.data)
        return Written()
    if isinstance(request, SignRequest):
        return Signature(await host.sign(request.algorithm, request.data))
    return TimestampResponse(await host.timestamp(request.url, request.body))


async def _answer_read(host: AsyncReadHost, request: Request) -> _Outcome:
    try:
        return await _read_reply(host, request), None
    except Exception as error:
        return _failed(error), error


async def _answer_build(host: AsyncBuildHost, request: BuildRequest) -> _Outcome:
    try:
        return await _build_reply(host, request), None
    except Exception as error:
        return _failed(error), error


async def _abandon(pending: "dict[asyncio.Task[_Outcome], int]") -> None:
    """Cancel what is still in flight and let it unwind, so nothing outlives the driver."""
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def _pump(
    session: Any, answer: Callable[[Any], Coroutine[Any, Any, _Outcome]], *, chain: bool
) -> Any:
    pending: dict[asyncio.Task[_Outcome], int] = {}
    cause: Exception | None = None
    try:
        while True:
            step = session.advance()
            if step.done:
                return session.finish()
            for request in step.requests:
                pending[asyncio.create_task(answer(request))] = request.id
            if not pending:
                raise _stalled()
            finished, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                request_id = pending.pop(task)
                if task.cancelled():
                    reply: Any = Failed("the host operation was cancelled")
                    failure: Exception | None = RuntimeError("the host operation was cancelled")
                else:
                    reply, failure = task.result()
                cause = failure or cause
                session.fulfill(request_id, reply)
    except C2paError as error:
        if not chain or cause is None:
            raise
        raise error from cause
    finally:
        await _abandon(pending)


async def async_drive_read(session: ReadSession, host: AsyncReadHost) -> Reader | None:
    """Run `session` to completion, answering its requests concurrently from `host`.

    Returns `None` for an asset without Content Credentials. On failure or cancellation,
    in-flight host calls are cancelled and the session is left for the caller to close.
    """
    reader: Reader | None = await _pump(
        session, lambda request: _answer_read(host, request), chain=False
    )
    return reader


async def async_drive_build(session: BuildSession, host: AsyncBuildHost) -> SignReport:
    """Run `session` to completion, answering its requests concurrently from `host`.

    Any host failure fails the build; the resulting `C2paError` is chained to the host
    exception that caused it.
    """
    report: SignReport = await _pump(
        session, lambda request: _answer_build(host, request), chain=True
    )
    return report


def _split(function: object | None) -> tuple[Any, Any]:
    """`(blocking, awaited)`: a coroutine function runs on the loop, anything else in a thread."""
    if function is not None and is_coroutine_function(function):
        return None, function
    return function, None


async def async_read_asset(
    source: ReadSource,
    format: str | None = None,
    settings_json: str | None = None,
    *,
    clock: Clock | None = None,
    ocsp: OcspTransport | AsyncOcspTransport | None = None,
) -> Reader | None:
    """The asyncio counterpart of `read_asset`, with the same arguments and results.

    Reading a path or stream happens in a worker thread; `ocsp` may be a coroutine function.
    If cancelled, the file this function opened is closed only once any read already in a
    worker thread has finished. A stream passed in stays the caller's: do not close it until
    this call has returned or you have waited for it to go idle.
    """
    blocking_ocsp, awaited_ocsp = _split(ocsp)
    release: Callable[[], object] | None = None
    inline = False
    host: ReadHost
    if isinstance(source, str | os.PathLike):
        asset_format = _format_of(source, format)
        stream = open(source, "rb")
        release = stream.close
        host = StreamReadHost(stream, clock=clock, ocsp=blocking_ocsp)
    else:
        if format is None:
            raise ValueError("format is required when the source is not a file path")
        asset_format = format
        if isinstance(source, bytes | bytearray | memoryview):
            host = BytesReadHost(source, clock=clock, ocsp=blocking_ocsp)
            inline = True
        else:
            host = StreamReadHost(source, clock=clock, ocsp=blocking_ocsp)
    adapter = ThreadReadHost(host, ocsp=awaited_ocsp, inline=inline)
    try:
        with ReadSession(asset_format, settings_json) as session:
            return await async_drive_read(session, adapter)
    finally:
        adapter.close_when_idle(release)


async def async_sign_file(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    definition_json: str,
    certificates: Sequence[Buffer],
    signer: Signer | AsyncSigner,
    algorithm: str = "es256",
    format: str | None = None,
    timestamper: Timestamper | AsyncTimestamper | None = None,
) -> SignReport:
    """The asyncio counterpart of `sign_file`, with the same arguments and guarantees.

    A coroutine-function `signer` or `timestamper` (a remote signing service, say) is
    awaited on the loop, concurrently with the file I/O; anything else is called in the
    worker thread. Wrap the call in `asyncio.timeout()` to bound a slow remote signer.

    If cancelled, a worker thread's operation that is already running cannot be revoked, so
    the temporary output is removed only once it has finished; the destination is never left
    partial. A cancellation that lands during the final rename may or may not replace the
    destination, but whatever it holds is complete.
    """
    blocking_signer, awaited_signer = _split(signer)
    blocking_timestamper, awaited_timestamper = _split(timestamper)
    with BuildSession(
        definition_json, _format_of(source, format), algorithm, certificates
    ) as session:
        files = FileBuildHost(
            source, destination, signer=blocking_signer, timestamper=blocking_timestamper
        )
        host = ThreadBuildHost(files, signer=awaited_signer, timestamper=awaited_timestamper)
        try:
            report = await async_drive_build(session, host)
            await host.run(files.publish)
        finally:
            host.close_when_idle(files.close)
    return report
