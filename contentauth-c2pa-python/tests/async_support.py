"""Hosts and helpers for driving sessions under asyncio, with cancellation at any point."""

import asyncio
from collections.abc import Coroutine
import gc
import threading
from typing import Any, TypeVar

import contentauth_c2pa as c2pa
from contentauth_c2pa import BuildStream
from support import JPEG, NOW, es256_sign

T = TypeVar("T")
SOURCE, OUTPUT = BuildStream.SOURCE, BuildStream.OUTPUT


def run(coroutine: Coroutine[Any, Any, T], timeout: float = 30) -> T:
    """Run to completion on a fresh loop; any unretrieved task exception or stray task fails."""
    problems: list[dict[str, Any]] = []

    async def main() -> T:
        asyncio.get_running_loop().set_exception_handler(lambda loop, context: problems.append(context))
        try:
            return await asyncio.wait_for(coroutine, timeout)
        finally:
            gc.collect()
            await asyncio.sleep(0)
            strays = asyncio.all_tasks() - {asyncio.current_task()}
            assert not strays, f"tasks outlived the test: {strays}"

    result = asyncio.run(main())
    gc.collect()
    assert not problems, f"the event loop reported: {problems}"
    return result


class Gates:
    """Lets a test hold a host operation open, learn when it starts, and see it cancelled."""

    def __init__(self, *blocked: str) -> None:
        self.blocked = set(blocked)
        self.entered: dict[str, asyncio.Event] = {}
        self.cancelled: list[str] = []
        self.completed: list[str] = []
        self.release = asyncio.Event()

    async def gate(self, kind: str) -> None:
        self.entered.setdefault(kind, asyncio.Event()).set()
        if kind not in self.blocked:
            await asyncio.sleep(0)
            return
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.append(kind)
            raise
        self.completed.append(kind)

    async def reached(self, kind: str) -> None:
        await asyncio.wait_for(self.entered.setdefault(kind, asyncio.Event()).wait(), 10)


class AsyncMemoryRead(c2pa.AsyncReadHost):
    def __init__(self, data: bytes = JPEG, gates: Gates | None = None, now: int = NOW) -> None:
        self.data = data
        self.gates = gates or Gates()
        self.clock = now
        self.in_flight = 0
        self.max_in_flight = 0
        self.log: list[str] = []

    async def _enter(self, kind: str) -> None:
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.log.append(kind)
        try:
            await self.gates.gate(kind)
        finally:
            self.in_flight -= 1

    async def read(self, start: int, length: int) -> bytes:
        await self._enter("read")
        return self.data[start : start + length]

    async def length(self) -> int:
        await self._enter("length")
        return len(self.data)

    async def now(self) -> int:
        await self._enter("time")
        return self.clock


class AsyncMemoryBuild(c2pa.AsyncBuildHost):
    def __init__(self, source: bytes = JPEG, gates: Gates | None = None, sign: bool = True) -> None:
        self.source = source
        self.output = bytearray()
        self.gates = gates or Gates()
        self.sign_with = (lambda data: es256_sign(data)) if sign else None
        self.timestamper: Any = None
        self.in_flight = 0
        self.max_in_flight = 0
        self.log: list[str] = []

    async def _enter(self, kind: str) -> None:
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.log.append(kind)
        try:
            await self.gates.gate(kind)
        finally:
            self.in_flight -= 1

    async def read(self, stream: BuildStream, start: int, length: int) -> bytes:
        await self._enter("read")
        data = self.source if stream is SOURCE else self.output
        return bytes(data[start : start + length])

    async def length(self, stream: BuildStream) -> int:
        await self._enter("length")
        return len(self.source if stream is SOURCE else self.output)

    async def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        await self._enter("write")
        self.output.extend(bytes(max(0, offset + len(data) - len(self.output))))
        self.output[offset : offset + len(data)] = data

    async def sign(self, algorithm: str, data: bytes) -> bytes:
        await self._enter("sign")
        if self.sign_with is None:
            raise PermissionError("no key")
        return self.sign_with(data)

    async def timestamp(self, url: str, body: bytes) -> bytes:
        await self._enter("timestamp")
        if self.timestamper is None:
            raise ConnectionError("no timestamp authority")
        return self.timestamper(body)


class WorkerGate:
    """Blocks a *worker thread* until released, and records which thread ran what."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.threads: list[int] = []

    def block(self) -> None:
        self.threads.append(threading.get_ident())
        self.entered.set()
        assert self.release.wait(10), "the worker was never released"

    async def reached(self) -> None:
        assert await asyncio.to_thread(self.entered.wait, 10), "the worker never started"


async def eventually(condition: Any, timeout: float = 10) -> None:
    """Wait for something a worker thread will do, without sleeping a fixed time."""
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.005)
