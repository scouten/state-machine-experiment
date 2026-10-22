"""Asynchronous hosts, and the adapter that lets a blocking host serve an event loop.

An `AsyncReadHost` or `AsyncBuildHost` answers one request per awaited call, so a
slow disk, network or remote signer never blocks the loop and independent requests
can be in flight together.

**Cancellation and lifetime.** Cancelling a task stops *awaiting* an operation; it
cannot stop a worker thread that is already running it. `ThreadReadHost` and
`ThreadBuildHost` therefore track every operation they have started, and
`close_when_idle()` defers releasing the underlying resources (a file, a temporary
output) until the last such operation has actually finished, on whichever thread that
happens. Nothing is ever closed under a running worker, and nothing is replied to a
session that has already been closed.
"""

from abc import ABC, abstractmethod
import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import Future, ThreadPoolExecutor
import contextlib
import inspect
import threading
import time
from types import TracebackType
from typing import Any, Self, TypeVar

from .hosts import BuildHost, ReadHost
from .vocab import Buffer, BuildStream

T = TypeVar("T")

AsyncOcspTransport = Callable[[str, bytes], Awaitable[Buffer]]
AsyncSigner = Callable[[str, bytes], Awaitable[Buffer]]
AsyncTimestamper = Callable[[str, bytes], Awaitable[Buffer]]


def is_coroutine_function(function: object) -> bool:
    """True for `async def` functions and for objects whose `__call__` is one."""
    return inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(
        getattr(function, "__call__", None)
    )


# ---- abstract async hosts ----------------------------------------------------


class AsyncReadHost(ABC):
    """Answers a read session's requests about one asset, awaiting each."""

    @abstractmethod
    async def read(self, start: int, length: int) -> Buffer:
        """Return exactly `length` bytes starting at `start`; never a short read."""

    @abstractmethod
    async def length(self) -> int:
        """The asset's length in bytes."""

    async def now(self) -> int:
        """The wall clock in Unix seconds."""
        return int(time.time())

    async def ocsp(self, url: str, body: bytes) -> Buffer:
        """One OCSP round trip; by default the responder is unreachable."""
        raise ConnectionError("no network access")


class AsyncBuildHost(ABC):
    """Answers a build session's requests: source, output, key and timestamp authority."""

    @abstractmethod
    async def read(self, stream: BuildStream, start: int, length: int) -> Buffer:
        """Return exactly `length` bytes of `stream` at `start`; never a short read."""

    @abstractmethod
    async def length(self, stream: BuildStream) -> int:
        """The current length of `stream`."""

    @abstractmethod
    async def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        """Write all of `data` at `offset` so later reads see it; only OUTPUT is writable."""

    async def sign(self, algorithm: str, data: bytes) -> Buffer:
        raise PermissionError("no signer is configured")

    async def timestamp(self, url: str, body: bytes) -> Buffer:
        raise ConnectionError("no timestamp transport is configured")


# ---- running blocking code without outliving its resources -------------------


class _Offload:
    """Runs blocking calls in worker threads and tracks them until they truly finish.

    Calls run FIFO on `max_workers` threads (one by default, so a host that is not
    thread-safe never sees concurrent calls). `inline` runs them on the event loop
    instead, for hosts that never block, such as in-memory ones.
    """

    def __init__(self, *, max_workers: int = 1, inline: bool = False) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self._inline = inline
        self._executor = None if inline else ThreadPoolExecutor(max_workers=max_workers)
        self._lock = threading.Lock()
        self._in_flight = 0
        self._closing = False
        self._released = False
        self._releases: list[Callable[[], object]] = []
        self._idle_waiters: list[tuple[asyncio.AbstractEventLoop, asyncio.Future[None]]] = []

    @property
    def in_flight(self) -> int:
        """Operations started and not yet finished, including ones whose awaiter was cancelled."""
        with self._lock:
            return self._in_flight

    async def run(self, function: Callable[..., T], *arguments: Any) -> T:
        """Call `function` off the loop, serialized with this host's other calls."""
        if self._inline:
            return function(*arguments)
        assert self._executor is not None
        with self._lock:
            if self._closing:
                raise RuntimeError("the host is closed")
            self._in_flight += 1
        try:
            future = self._executor.submit(function, *arguments)
        except BaseException:
            self._finished()
            raise
        future.add_done_callback(self._on_done)
        return await asyncio.wrap_future(future)

    def _on_done(self, future: "Future[Any]") -> None:
        self._finished()

    def _finished(self) -> None:
        with self._lock:
            self._in_flight -= 1
            if self._in_flight:
                return
            waiters, self._idle_waiters = self._idle_waiters, []
            release = self._closing and not self._released
            self._released = self._released or release
        for loop, waiter in waiters:
            with contextlib.suppress(RuntimeError):  # the loop may already be closed
                loop.call_soon_threadsafe(_resolve, waiter)
        if release:
            self._release()

    def _release(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False)
        failure: Exception | None = None
        for release in self._releases:
            try:
                release()
            except Exception as error:
                failure = failure or error
        self._releases = []
        if failure is not None:
            raise failure

    def close_when_idle(self, release: Callable[[], object] | None = None) -> None:
        """Refuse new calls and run `release` once nothing is running; repeatable.

        If calls are still running (even ones whose awaiter was cancelled), `release` runs
        on the thread that finishes the last of them. If the host is already idle it runs
        now. Never blocks.
        """
        with self._lock:
            self._closing = True
            if self._released:
                run_now = [release] if release is not None else []
                run_all = False
            else:
                run_now = []
                if release is not None:
                    self._releases.append(release)
                run_all = self._in_flight == 0
                self._released = run_all
        if run_all:
            self._release()
        for late in run_now:
            late()  # everything was already released: this resource is idle too

    async def wait_idle(self) -> None:
        """Wait until every started call has finished, whether or not it was cancelled."""
        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()
        with self._lock:
            if self._in_flight == 0:
                return
            self._idle_waiters.append((loop, waiter))
        await waiter

    async def aclose(self) -> None:
        """`close_when_idle()` and then wait for the host to go idle."""
        self.close_when_idle()
        await self.wait_idle()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


def _resolve(waiter: "asyncio.Future[None]") -> None:
    if not waiter.done():
        waiter.set_result(None)


class ThreadReadHost(_Offload, AsyncReadHost):
    """Serve a blocking `ReadHost` to the event loop through worker threads.

    The wrapped host's calls are serialized unless `max_workers` is raised. Do not close or
    reuse what the host reads (a stream, say) until `wait_idle()` returns or you have passed
    its release to `close_when_idle()`. `ocsp` may be an async transport, awaited on the loop
    instead of the host's own.
    """

    def __init__(
        self,
        host: ReadHost,
        *,
        ocsp: AsyncOcspTransport | None = None,
        max_workers: int = 1,
        inline: bool = False,
    ) -> None:
        _Offload.__init__(self, max_workers=max_workers, inline=inline)
        self._host = host
        self._async_ocsp = ocsp

    async def read(self, start: int, length: int) -> Buffer:
        return await self.run(self._host.read, start, length)

    async def length(self) -> int:
        return await self.run(self._host.length)

    async def now(self) -> int:
        return await self.run(self._host.now)

    async def ocsp(self, url: str, body: bytes) -> Buffer:
        if self._async_ocsp is not None:
            return await self._async_ocsp(url, body)
        return await self.run(self._host.ocsp, url, body)


class ThreadBuildHost(_Offload, AsyncBuildHost):
    """Serve a blocking `BuildHost` to the event loop through worker threads.

    `signer` and `timestamper` may be coroutine functions (a remote signing service, say)
    and are then awaited on the loop, concurrently with the host's file I/O; otherwise the
    host's own blocking ones run in a worker thread. See `ThreadReadHost` for lifetime rules.
    """

    def __init__(
        self,
        host: BuildHost,
        *,
        signer: AsyncSigner | None = None,
        timestamper: AsyncTimestamper | None = None,
        max_workers: int = 1,
        inline: bool = False,
    ) -> None:
        _Offload.__init__(self, max_workers=max_workers, inline=inline)
        self._host = host
        self._async_signer = signer
        self._async_timestamper = timestamper

    async def read(self, stream: BuildStream, start: int, length: int) -> Buffer:
        return await self.run(self._host.read, stream, start, length)

    async def length(self, stream: BuildStream) -> int:
        return await self.run(self._host.length, stream)

    async def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        await self.run(self._host.write, stream, offset, data)

    async def sign(self, algorithm: str, data: bytes) -> Buffer:
        if self._async_signer is not None:
            return await self._async_signer(algorithm, data)
        return await self.run(self._host.sign, algorithm, data)

    async def timestamp(self, url: str, body: bytes) -> Buffer:
        if self._async_timestamper is not None:
            return await self._async_timestamper(url, body)
        return await self.run(self._host.timestamp, url, body)
