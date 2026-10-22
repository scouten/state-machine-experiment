import asyncio
import threading
import time

import pytest

import contentauth_c2pa as c2pa
from contentauth_c2pa import BuildStream, async_hosts
from async_support import SOURCE, OUTPUT, WorkerGate, eventually, run


class Recording(c2pa.ReadHost):
    """A blocking host that notes the thread and concurrency of every call."""

    def __init__(self, gate: WorkerGate | None = None, pause: float = 0) -> None:
        super().__init__()
        self.gate = gate
        self.pause = pause
        self.threads: list[int] = []
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def _enter(self) -> None:
        self.threads.append(threading.get_ident())
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.gate is not None:
                self.gate.block()
            time.sleep(self.pause)
        finally:
            with self._lock:
                self.active -= 1

    def read(self, start: int, length: int) -> bytes:
        self._enter()
        return b"r" * length

    def length(self) -> int:
        self._enter()
        return 7

    def now(self) -> int:
        self._enter()
        return 1234

    def ocsp(self, url: str, body: bytes) -> bytes:
        self._enter()
        return b"sync:" + body


# ---- where calls run ---------------------------------------------------------


def test_blocking_calls_run_in_a_worker_thread_not_on_the_loop() -> None:
    async def scenario() -> None:
        host, adapter = Recording(), None
        adapter = c2pa.ThreadReadHost(host)
        assert await adapter.read(0, 3) == b"rrr"
        assert await adapter.length() == 7
        assert await adapter.now() == 1234
        assert await adapter.ocsp("u", b"q") == b"sync:q"
        assert host.threads and threading.get_ident() not in host.threads
        await adapter.aclose()

    run(scenario())


def test_inline_calls_run_on_the_loop_for_hosts_that_never_block() -> None:
    async def scenario() -> None:
        host = Recording()
        adapter = c2pa.ThreadReadHost(host, inline=True)
        assert await adapter.read(0, 2) == b"rr"
        assert set(host.threads) == {threading.get_ident()}
        assert adapter.in_flight == 0
        adapter.close_when_idle()
        await adapter.wait_idle()

    run(scenario())


def test_an_async_ocsp_transport_runs_on_the_loop() -> None:
    seen: list[int] = []

    async def transport(url: str, body: bytes) -> bytes:
        seen.append(threading.get_ident())
        return b"async:" + body

    async def scenario() -> None:
        host = Recording()
        async with c2pa.ThreadReadHost(host, ocsp=transport) as adapter:
            assert await adapter.ocsp("u", b"q") == b"async:q"
        assert seen == [threading.get_ident()] and not host.threads

    run(scenario())


def test_async_signer_and_timestamper_run_on_the_loop_and_others_in_a_thread() -> None:
    seen: list[int] = []

    async def signer(algorithm: str, data: bytes) -> bytes:
        seen.append(threading.get_ident())
        return b"remote-sig"

    async def stamper(url: str, body: bytes) -> bytes:
        seen.append(threading.get_ident())
        return b"remote-tsr"

    async def scenario() -> None:
        local = c2pa.MemoryBuildHost(b"abc", signer=lambda a, d: b"local-sig", timestamper=lambda u, b: b"local-tsr")
        async with c2pa.ThreadBuildHost(local, signer=signer, timestamper=stamper) as remote:
            assert await remote.sign("es256", b"x") == b"remote-sig"
            assert await remote.timestamp("u", b"x") == b"remote-tsr"
        async with c2pa.ThreadBuildHost(local) as plain:
            assert await plain.sign("es256", b"x") == b"local-sig"
            assert await plain.timestamp("u", b"x") == b"local-tsr"
        assert seen == [threading.get_ident()] * 2

    run(scenario())


def test_every_build_host_method_is_forwarded() -> None:
    async def scenario() -> None:
        async with c2pa.ThreadBuildHost(c2pa.MemoryBuildHost(b"source"), inline=True) as host:
            await host.write(OUTPUT, 2, b"ab")
            assert await host.length(OUTPUT) == 4 and await host.length(SOURCE) == 6
            assert bytes(await host.read(OUTPUT, 2, 2)) == b"ab"
            with pytest.raises(PermissionError):
                await host.sign("es256", b"")
            with pytest.raises(ConnectionError):
                await host.timestamp("u", b"")

    run(scenario())


def test_abstract_async_hosts_have_conservative_defaults() -> None:
    class Read(c2pa.AsyncReadHost):
        async def read(self, start: int, length: int) -> bytes:
            return b""

        async def length(self) -> int:
            return 0

    class Build(c2pa.AsyncBuildHost):
        async def read(self, stream: BuildStream, start: int, length: int) -> bytes:
            return b""

        async def length(self, stream: BuildStream) -> int:
            return 0

        async def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
            return None

    async def scenario() -> None:
        assert abs(await Read().now() - time.time()) < 5
        with pytest.raises(ConnectionError, match="no network"):
            await Read().ocsp("u", b"")
        with pytest.raises(PermissionError, match="no signer"):
            await Build().sign("es256", b"")
        with pytest.raises(ConnectionError, match="no timestamp"):
            await Build().timestamp("u", b"")

    run(scenario())


class AsyncCallable:
    async def __call__(self, algorithm: str, data: bytes) -> bytes:
        return b""


def test_coroutine_functions_are_told_apart_from_blocking_callables() -> None:
    async def coroutine_function(a: str, d: bytes) -> bytes:
        return b""

    assert async_hosts.is_coroutine_function(coroutine_function)
    assert async_hosts.is_coroutine_function(AsyncCallable())
    assert not async_hosts.is_coroutine_function(lambda a, d: b"")
    assert not async_hosts.is_coroutine_function(None)


# ---- serialization and concurrency -------------------------------------------


def test_calls_are_serialized_by_default_so_unsafe_hosts_are_safe() -> None:
    async def scenario() -> None:
        host = Recording(pause=0.01)
        async with c2pa.ThreadReadHost(host) as adapter:
            results = await asyncio.gather(*(adapter.read(0, i) for i in range(1, 7)))
        assert results == [b"r" * i for i in range(1, 7)]  # FIFO and exact
        assert host.max_active == 1

    run(scenario())


def test_more_workers_allow_concurrent_calls_for_thread_safe_hosts() -> None:
    async def scenario() -> None:
        host = Recording(pause=0.05)
        async with c2pa.ThreadReadHost(host, max_workers=4) as adapter:
            await asyncio.gather(*(adapter.length() for _ in range(4)))
        assert host.max_active >= 2

    run(scenario())


def test_at_least_one_worker_is_required() -> None:
    with pytest.raises(ValueError, match="max_workers"):
        c2pa.ThreadReadHost(Recording(), max_workers=0)


# ---- cancellation and lifetime -----------------------------------------------


def test_a_cancelled_call_keeps_its_resources_until_the_worker_really_finishes() -> None:
    async def scenario() -> None:
        gate = WorkerGate()
        adapter = c2pa.ThreadReadHost(Recording(gate))
        released: list[int] = []
        task = asyncio.create_task(adapter.read(0, 3))
        await gate.reached()

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert adapter.in_flight == 1  # the awaiter is gone; the worker is not

        adapter.close_when_idle(lambda: released.append(threading.get_ident()))
        await asyncio.sleep(0.05)
        assert released == []  # nothing is closed under a running worker

        gate.release.set()
        await adapter.wait_idle()
        await eventually(lambda: released)
        assert released != [threading.get_ident()]  # released by the worker that finished last
        assert adapter.in_flight == 0

    run(scenario())


def test_a_call_cancelled_before_it_starts_still_lets_the_host_go_idle() -> None:
    async def scenario() -> None:
        gate = WorkerGate()
        adapter = c2pa.ThreadReadHost(Recording(gate))
        first = asyncio.create_task(adapter.read(0, 1))
        await gate.reached()
        queued = asyncio.create_task(adapter.length())  # waiting behind the blocked worker
        await asyncio.sleep(0.02)
        assert adapter.in_flight == 2

        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        assert adapter.in_flight == 1  # its bookkeeping did not wait for a worker

        gate.release.set()
        assert await first == b"r"
        await adapter.aclose()
        assert adapter.in_flight == 0

    run(scenario())


def test_a_closed_host_refuses_new_calls_without_counting_them() -> None:
    async def scenario() -> None:
        adapter = c2pa.ThreadReadHost(Recording())
        adapter.close_when_idle()
        with pytest.raises(RuntimeError, match="the host is closed"):
            await adapter.read(0, 1)
        assert adapter.in_flight == 0

    run(scenario())


def test_waiting_for_idle_survives_being_cancelled() -> None:
    async def scenario() -> None:
        gate = WorkerGate()
        adapter = c2pa.ThreadReadHost(Recording(gate))
        call = asyncio.create_task(adapter.read(0, 1))
        await gate.reached()
        impatient = asyncio.create_task(adapter.wait_idle())
        patient = asyncio.create_task(adapter.wait_idle())
        await asyncio.sleep(0.02)
        impatient.cancel()
        with pytest.raises(asyncio.CancelledError):
            await impatient
        gate.release.set()
        await call
        await patient  # still resolved, and the cancelled waiter did not break it

    run(scenario())


def test_waiting_for_an_idle_host_returns_immediately() -> None:
    async def scenario() -> None:
        await c2pa.ThreadReadHost(Recording()).wait_idle()

    run(scenario())


def test_a_waiter_whose_loop_is_gone_does_not_break_the_worker() -> None:
    async def scenario() -> None:
        adapter = c2pa.ThreadReadHost(Recording())
        dead = asyncio.new_event_loop()
        waiter = dead.create_future()
        dead.close()
        adapter._idle_waiters.append((dead, waiter))
        adapter._in_flight = 1
        adapter._finished()  # must not raise although the waiter's loop is closed
        assert adapter.in_flight == 0

    run(scenario())


# ---- releasing ---------------------------------------------------------------


def test_closing_an_idle_host_releases_now_and_stops_its_workers() -> None:
    async def scenario() -> None:
        adapter = c2pa.ThreadReadHost(Recording())
        await adapter.read(0, 1)
        released: list[str] = []
        adapter.close_when_idle(lambda: released.append("first"))
        assert released == ["first"]
        adapter.close_when_idle(lambda: released.append("later"))  # already idle: runs at once
        adapter.close_when_idle()
        assert released == ["first", "later"]
        with pytest.raises(RuntimeError):
            adapter._executor.submit(lambda: None)  # type: ignore[union-attr]

    run(scenario())


def test_every_release_runs_even_when_one_fails() -> None:
    async def scenario() -> None:
        adapter = c2pa.ThreadReadHost(Recording())
        ran: list[str] = []

        def boom() -> None:
            raise OSError("cannot close")

        with pytest.raises(OSError, match="cannot close"):
            adapter.close_when_idle(boom)
        adapter.close_when_idle(lambda: ran.append("second"))
        assert ran == ["second"]

    async def scenario_failing_first_among_many() -> None:
        adapter = c2pa.ThreadReadHost(Recording(), inline=True)
        ran: list[str] = []
        adapter._releases = [lambda: (_ for _ in ()).throw(OSError("one")), lambda: ran.append("two")]
        with pytest.raises(OSError, match="one"):
            adapter.close_when_idle()
        assert ran == ["two"]

    run(scenario())
    run(scenario_failing_first_among_many())


def test_a_failing_release_after_cancellation_does_not_hide_the_cancellation() -> None:
    async def scenario() -> None:
        gate = WorkerGate()
        adapter = c2pa.ThreadReadHost(Recording(gate))
        task = asyncio.create_task(adapter.read(0, 1))
        await gate.reached()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        adapter.close_when_idle(lambda: (_ for _ in ()).throw(OSError("late")))
        gate.release.set()
        await adapter.wait_idle()  # the worker, not the loop, hit the failure

    run(scenario())


def test_async_with_closes_the_host_and_waits_for_it() -> None:
    async def scenario() -> None:
        released: list[int] = []
        async with c2pa.ThreadReadHost(Recording()) as adapter:
            adapter.close_when_idle(lambda: released.append(1))
            assert released == [1]
        with pytest.raises(RuntimeError):
            await adapter.length()

    run(scenario())


def test_a_refused_submission_is_not_left_counted() -> None:
    async def scenario() -> None:
        adapter = c2pa.ThreadReadHost(Recording())
        adapter._executor.shutdown()  # type: ignore[union-attr]
        with pytest.raises(RuntimeError, match="shutdown"):
            await adapter.read(0, 1)
        assert adapter.in_flight == 0

    run(scenario())
