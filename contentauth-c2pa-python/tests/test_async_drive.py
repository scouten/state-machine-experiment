import asyncio
import io
import os
from pathlib import Path
import threading
from typing import Any

import pytest

import contentauth_c2pa as c2pa
from contentauth_c2pa import (
    BuildLengthRequest,
    BuildSession,
    BuildStep,
    C2paError,
    ErrorCode,
    LengthRequest,
    ReadRequest,
    ReadSession,
    Step,
    ValidationState,
    async_drive,
    hosts,
)
from async_support import (
    OUTPUT,
    SOURCE,
    AsyncMemoryBuild,
    AsyncMemoryRead,
    Gates,
    WorkerGate,
    eventually,
    run,
)
from support import CERTIFICATE, JPEG, NOW, baseline_definition, es256_sign, trust_settings


def fds() -> int:
    return len(os.listdir("/dev/fd"))


def names(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def new_session(definition: str | None = None) -> BuildSession:
    return BuildSession(definition or baseline_definition(), "image/jpeg", "es256", [CERTIFICATE])


def trusted(asset: bytes) -> bool:
    reader = c2pa.read_asset(asset, "jpeg", trust_settings(), clock=lambda: NOW)
    return reader is not None and reader.validation_state() is ValidationState.TRUSTED


def sync_signed() -> bytes:
    host = c2pa.MemoryBuildHost(JPEG, signer=lambda a, d: es256_sign(d))
    c2pa.drive_build(new_session(), host)
    return host.output


class Stub:
    """A session that replays scripted steps, for protocol paths a real one will not take."""

    def __init__(self, *steps: Any) -> None:
        self.steps = list(steps)
        self.fulfilled: list[tuple[int, Any]] = []

    def advance(self) -> Any:
        return self.steps.pop(0)

    def fulfill(self, request_id: int, reply: Any) -> None:
        self.fulfilled.append((request_id, reply))

    def finish(self) -> str:
        return "finished"


# ---- driving to completion ---------------------------------------------------


def test_async_read_matches_the_blocking_driver() -> None:
    expected = c2pa.read_asset(JPEG, "jpeg", clock=lambda: NOW)
    assert expected is not None

    async def scenario() -> None:
        with ReadSession("jpeg") as session:
            reader = await c2pa.async_drive_read(session, AsyncMemoryRead())
        assert reader is not None and reader.json() == expected.json()

    run(scenario())


def test_async_read_of_an_unsigned_or_malformed_asset() -> None:
    async def scenario() -> None:
        with ReadSession("jpeg") as session:
            assert await c2pa.async_drive_read(session, AsyncMemoryRead(b"\xff\xd8\xff\xd9")) is None
        with ReadSession("jpeg") as session, pytest.raises(C2paError) as failure:
            await c2pa.async_drive_read(session, AsyncMemoryRead(b"not a jpeg"))
        assert failure.value.code is ErrorCode.READ

    run(scenario())


def test_async_build_matches_the_blocking_driver_and_reads_back_trusted() -> None:
    async def scenario() -> None:
        host = AsyncMemoryBuild()
        with new_session() as session:
            report = await c2pa.async_drive_build(session, host)
        assert bytes(host.output) == sync_signed()
        assert report.manifest and trusted(bytes(host.output))

    run(scenario())


def test_the_threaded_adapter_serves_the_async_driver() -> None:
    async def scenario() -> None:
        memory = c2pa.MemoryBuildHost(JPEG, signer=lambda a, d: es256_sign(d))
        async with c2pa.ThreadBuildHost(memory) as host:
            with new_session() as session:
                await c2pa.async_drive_build(session, host)
        assert memory.output == sync_signed()

    run(scenario())


# ---- concurrency and fairness ------------------------------------------------


def test_independent_requests_are_in_flight_together() -> None:
    async def scenario() -> None:
        read, build = AsyncMemoryRead(), AsyncMemoryBuild()
        with ReadSession("jpeg") as session:
            await c2pa.async_drive_read(session, read)
        with new_session() as session:
            await c2pa.async_drive_build(session, build)
        assert read.max_in_flight >= 2 and build.max_in_flight >= 2

    run(scenario())


def test_replies_finishing_out_of_order_give_the_same_answer() -> None:
    class Backwards(AsyncMemoryBuild):
        async def _enter(self, kind: str) -> None:
            self.log.append(kind)
            await asyncio.sleep(0.02 if kind == "length" else 0)

    async def scenario() -> None:
        host = Backwards()
        with new_session() as session:
            await c2pa.async_drive_build(session, host)
        assert bytes(host.output) == sync_signed()

    run(scenario())


def test_two_sessions_interleave_on_one_loop_at_every_request() -> None:
    events: list[str] = []

    class Tracing(AsyncMemoryRead):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

        async def _enter(self, kind: str) -> None:
            events.append(self.name)
            await super()._enter(kind)

    async def one(name: str) -> None:
        with ReadSession("jpeg") as session:
            assert await c2pa.async_drive_read(session, Tracing(name)) is not None

    async def scenario() -> None:
        await asyncio.gather(one("a"), one("b"))
        first_b, last_a = events.index("b"), len(events) - 1 - events[::-1].index("a")
        first_a, last_b = events.index("a"), len(events) - 1 - events[::-1].index("b")
        assert first_b < last_a and first_a < last_b  # neither ran to completion first

    run(scenario())


def test_the_event_loop_keeps_running_while_a_session_waits_on_slow_hosts() -> None:
    class Slow(AsyncMemoryBuild):
        async def _enter(self, kind: str) -> None:
            await asyncio.sleep(0.005)

    async def scenario() -> None:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.001)

        watcher = asyncio.create_task(ticker())
        with new_session() as session:
            await c2pa.async_drive_build(session, Slow())
        watcher.cancel()
        assert ticks > 10

    run(scenario())


# ---- failures ----------------------------------------------------------------


def test_an_async_host_failure_fails_the_build_and_names_the_cause() -> None:
    async def scenario() -> None:
        with new_session() as session, pytest.raises(C2paError) as failure:
            await c2pa.async_drive_build(session, AsyncMemoryBuild(sign=False))
        assert failure.value.code is ErrorCode.BUILD
        assert isinstance(failure.value.__cause__, PermissionError)
        assert "no key" in str(failure.value)

    run(scenario())


def test_an_engine_failure_without_a_host_failure_has_no_cause() -> None:
    async def scenario() -> None:
        with new_session() as session, pytest.raises(C2paError) as failure:
            await c2pa.async_drive_build(session, AsyncMemoryBuild(b"not a jpeg"))
        assert failure.value.__cause__ is None

    run(scenario())


def test_a_host_failure_is_reported_by_the_engine_when_reading() -> None:
    class Broken(AsyncMemoryRead):
        async def read(self, start: int, length: int) -> bytes:
            raise OSError("disk on fire")

    async def scenario() -> None:
        with ReadSession("jpeg") as session, pytest.raises(C2paError) as failure:
            await c2pa.async_drive_read(session, Broken())
        assert "disk on fire" in failure.value.message

    run(scenario())


def test_a_host_call_that_cancels_itself_is_a_failure_not_a_cancellation() -> None:
    class SelfCancelling(AsyncMemoryBuild):
        async def read(self, stream: Any, start: int, length: int) -> bytes:
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
            await asyncio.sleep(0)
            return b""

    async def scenario() -> None:
        with new_session() as session, pytest.raises(C2paError) as failure:
            await c2pa.async_drive_build(session, SelfCancelling())
        assert "the host operation was cancelled" in str(failure.value.__cause__)

    run(scenario())


def test_a_short_read_is_a_failure() -> None:
    class Short(AsyncMemoryRead):
        async def read(self, start: int, length: int) -> bytes:
            return b"x"

    async def scenario() -> None:
        with ReadSession("jpeg") as session, pytest.raises(C2paError):
            await c2pa.async_drive_read(session, Short())

    run(scenario())


def test_a_session_that_makes_no_progress_is_stopped() -> None:
    async def scenario() -> None:
        for drive, step in (
            (c2pa.async_drive_read, Step(done=False, requests=())),
            (c2pa.async_drive_build, BuildStep(done=False, requests=())),
        ):
            with pytest.raises(C2paError, match="reported no new requests") as failure:
                await drive(Stub(step), AsyncMemoryRead())  # type: ignore[arg-type]
            assert failure.value.name == "SessionStalled"

    run(scenario())


def test_ocsp_requests_are_answered_by_the_hosts_transport_or_fail_open() -> None:
    class WithOcsp(AsyncMemoryRead):
        async def ocsp(self, url: str, body: bytes) -> bytes:
            return url.encode() + body

    async def scenario() -> None:
        script = lambda: Stub(  # noqa: E731
            Step(done=False, requests=(c2pa.OcspRequest(5, "http://ocsp.example", b"q"),)),
            Step(done=True, requests=()),
        )
        answered, unreachable = script(), script()
        await c2pa.async_drive_read(answered, WithOcsp())  # type: ignore[arg-type]
        await c2pa.async_drive_read(unreachable, AsyncMemoryRead())  # type: ignore[arg-type]
        assert answered.fulfilled == [(5, c2pa.Ocsp(b"http://ocsp.exampleq"))]
        assert unreachable.fulfilled == [(5, c2pa.Failed("no network access"))]

    run(scenario())


def test_a_session_that_finishes_with_calls_in_flight_cancels_them() -> None:
    gates = Gates("read")

    async def scenario() -> None:
        stub = Stub(
            Step(done=False, requests=(LengthRequest(1), ReadRequest(2, 0, 1))),
            Step(done=True, requests=()),
        )
        host = AsyncMemoryRead(gates=gates)
        result = await c2pa.async_drive_read(stub, host)  # type: ignore[arg-type]
        assert result == "finished" and stub.fulfilled[0][0] == 1
        assert gates.cancelled == ["read"] and host.in_flight == 0

    run(scenario())


def test_the_build_driver_finishes_as_soon_as_the_session_is_done() -> None:
    async def scenario() -> None:
        stub = Stub(
            BuildStep(done=False, requests=(BuildLengthRequest(1, SOURCE),)),
            BuildStep(done=True, requests=()),
        )
        assert await c2pa.async_drive_build(stub, AsyncMemoryBuild()) == "finished"  # type: ignore[arg-type]
        assert stub.fulfilled[0][0] == 1

    run(scenario())


# ---- cancellation ------------------------------------------------------------


@pytest.mark.parametrize("kind", ["length", "time"])
def test_cancelling_a_read_cancels_the_host_call_and_leaves_the_session_closable(kind: str) -> None:
    async def scenario() -> None:
        gates = Gates(kind)
        host = AsyncMemoryRead(gates=gates)
        session = ReadSession("jpeg")
        driver = asyncio.create_task(c2pa.async_drive_read(session, host))
        await gates.reached(kind)

        driver.cancel()
        with pytest.raises(asyncio.CancelledError):
            await driver
        assert gates.cancelled == [kind]  # the call was cancelled and has unwound
        assert host.in_flight == 0
        session.close()

    run(scenario())


@pytest.mark.parametrize("kind", ["length", "read", "write", "sign", "timestamp"])
def test_cancelling_a_build_at_any_request_cancels_the_host_call(kind: str) -> None:
    async def scenario() -> None:
        gates = Gates(kind)
        host = AsyncMemoryBuild(gates=gates)
        host.timestamper = lambda body: b""
        definition = baseline_definition(timestamp_url="https://tsa.example/")
        session = new_session(definition)
        driver = asyncio.create_task(c2pa.async_drive_build(session, host))
        await gates.reached(kind)
        await asyncio.sleep(0.01)  # let everything independent of it finish

        driver.cancel()
        with pytest.raises(asyncio.CancelledError):
            await driver
        assert gates.cancelled == [kind] and host.in_flight == 0
        session.close()

    run(scenario())


def test_a_timeout_cancels_a_hanging_host() -> None:
    async def scenario() -> None:
        gates = Gates("sign")
        with new_session() as session, pytest.raises(TimeoutError):
            async with asyncio.timeout(0.2):
                await c2pa.async_drive_build(session, AsyncMemoryBuild(gates=gates))
        assert gates.cancelled == ["sign"]

    run(scenario())


def test_a_late_completion_is_never_delivered_to_a_cancelled_session() -> None:
    async def scenario() -> None:
        gates = Gates("read")
        stub = Stub(Step(done=False, requests=(ReadRequest(7, 0, 4),)))
        driver = asyncio.create_task(c2pa.async_drive_read(stub, AsyncMemoryRead(gates=gates)))  # type: ignore[arg-type]
        await gates.reached("read")
        driver.cancel()
        with pytest.raises(asyncio.CancelledError):
            await driver
        gates.release.set()
        await asyncio.sleep(0.05)
        assert stub.fulfilled == []

    run(scenario())


class BlockingWrite(c2pa.MemoryBuildHost):
    """A blocking host whose write holds a worker thread until released."""

    def __init__(self, gate: WorkerGate) -> None:
        super().__init__(JPEG, signer=lambda a, d: es256_sign(d))
        self.gate = gate
        self.finished_writes = 0

    def write(self, stream: Any, offset: int, data: bytes) -> None:
        self.gate.block()
        super().write(stream, offset, data)
        self.finished_writes += 1


def test_cancelling_while_a_worker_is_writing_lets_that_write_finish_harmlessly() -> None:
    async def scenario() -> None:
        gate = WorkerGate()
        host = BlockingWrite(gate)
        adapter = c2pa.ThreadBuildHost(host)
        released: list[int] = []
        session = new_session()
        driver = asyncio.create_task(c2pa.async_drive_build(session, adapter))
        await gate.reached()

        driver.cancel()
        with pytest.raises(asyncio.CancelledError):
            await driver
        session.close()  # the native session is gone while its host is still mid-write
        adapter.close_when_idle(lambda: released.append(1))
        assert adapter.in_flight == 1 and released == []

        gate.release.set()
        await adapter.wait_idle()
        await eventually(lambda: released)
        assert host.finished_writes == 1  # the late write ran to completion, safely

    run(scenario())


# ---- async_read_asset --------------------------------------------------------


@pytest.fixture
def photo(tmp_path: Path) -> Path:
    path = tmp_path / "photo.jpg"
    path.write_bytes(JPEG)
    return path


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview, io.BytesIO])
def test_async_read_asset_accepts_bytes_like_and_streams(wrap: Any) -> None:
    expected = c2pa.read_asset(JPEG, "jpeg", clock=lambda: NOW)
    assert expected is not None

    async def scenario() -> None:
        reader = await c2pa.async_read_asset(wrap(JPEG), "image/jpeg", clock=lambda: NOW)
        assert reader is not None and reader.json() == expected.json()

    run(scenario())


def test_async_read_asset_reads_paths_and_closes_what_it_opened(photo: Path) -> None:
    async def scenario() -> None:
        before = fds()
        for source in (photo, str(photo)):
            assert await c2pa.async_read_asset(source) is not None
        await eventually(lambda: fds() == before)
        stream = io.BytesIO(JPEG)
        assert await c2pa.async_read_asset(stream, "jpeg") is not None
        assert not stream.closed

    run(scenario())


def test_async_read_asset_reports_the_same_errors_as_read_asset(tmp_path: Path, photo: Path) -> None:
    bare = tmp_path / "photo"
    bare.write_bytes(JPEG)

    async def scenario() -> None:
        before = fds()
        with pytest.raises(ValueError, match="pass format="):
            await c2pa.async_read_asset(bare)
        with pytest.raises(ValueError, match="format is required"):
            await c2pa.async_read_asset(JPEG)
        with pytest.raises(FileNotFoundError):
            await c2pa.async_read_asset(tmp_path / "missing.jpg")
        with pytest.raises(C2paError):
            await c2pa.async_read_asset(photo, "image/xyz")  # the opened file is not leaked
        with pytest.raises(C2paError):
            await c2pa.async_read_asset(photo, settings_json="{not json")
        await eventually(lambda: fds() == before)

    run(scenario())


def test_async_read_asset_routes_the_clock_and_ocsp_to_the_right_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []

    async def capture(session: Any, host: Any) -> None:
        seen.append(host)

    async def remote(url: str, body: bytes) -> bytes:
        return b"remote:" + body

    monkeypatch.setattr(async_drive, "async_drive_read", capture)

    async def scenario() -> None:
        await c2pa.async_read_asset(JPEG, "jpeg", clock=lambda: 7, ocsp=remote)
        await c2pa.async_read_asset(
            JPEG, "jpeg", clock=lambda: 8, ocsp=lambda url, body: b"blocking:" + body
        )
        first, second = seen
        assert await first.now() == 7 and await first.ocsp("u", b"q") == b"remote:q"
        assert await second.now() == 8 and await second.ocsp("u", b"q") == b"blocking:q"

    run(scenario())


def test_cancelling_a_file_read_keeps_the_file_open_until_the_worker_finishes(
    photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = WorkerGate()
    real_read = hosts.StreamReadHost.read

    def blocked(self: Any, start: int, length: int) -> Any:
        gate.block()
        return real_read(self, start, length)

    monkeypatch.setattr(hosts.StreamReadHost, "read", blocked)

    async def scenario() -> None:
        before = fds()
        task = asyncio.create_task(c2pa.async_read_asset(photo))
        await gate.reached()
        assert fds() == before + 1  # the file we opened

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert fds() == before + 1  # still open: a worker is reading it

        gate.release.set()
        await eventually(lambda: fds() == before)  # closed only once that read finished

    run(scenario())


# ---- async_sign_file ---------------------------------------------------------


@pytest.fixture
def jpeg(tmp_path: Path) -> Path:
    path = tmp_path / "in.jpg"
    path.write_bytes(JPEG)
    return path


def arguments(**overrides: Any) -> dict[str, Any]:
    return {
        "definition_json": baseline_definition(),
        "certificates": [CERTIFICATE],
        "signer": lambda algorithm, data: es256_sign(data),
        **overrides,
    }


def test_async_sign_file_matches_the_blocking_helper_and_reads_back_trusted(
    tmp_path: Path, jpeg: Path
) -> None:
    c2pa.sign_file(jpeg, tmp_path / "sync.jpg", **arguments())

    async def scenario() -> None:
        report = await c2pa.async_sign_file(jpeg, tmp_path / "async.jpg", **arguments())
        assert report.manifest and report.exclusions

    run(scenario())
    assert (tmp_path / "async.jpg").read_bytes() == (tmp_path / "sync.jpg").read_bytes()
    assert trusted((tmp_path / "async.jpg").read_bytes())
    assert names(tmp_path) == ["async.jpg", "in.jpg", "sync.jpg"]


def test_a_coroutine_signer_runs_on_the_loop_and_a_blocking_one_in_a_thread(
    tmp_path: Path, jpeg: Path
) -> None:
    where: dict[str, int] = {}

    async def remote(algorithm: str, data: bytes) -> bytes:
        where["remote"] = threading.get_ident()
        await asyncio.sleep(0)
        return es256_sign(data)

    def local(algorithm: str, data: bytes) -> bytes:
        where["local"] = threading.get_ident()
        return es256_sign(data)

    async def scenario() -> None:
        await c2pa.async_sign_file(jpeg, tmp_path / "a.jpg", **arguments(signer=remote))
        await c2pa.async_sign_file(jpeg, tmp_path / "b.jpg", **arguments(signer=local))
        assert where["remote"] == threading.get_ident()
        assert where["local"] != threading.get_ident()

    run(scenario())
    assert trusted((tmp_path / "a.jpg").read_bytes()) and trusted((tmp_path / "b.jpg").read_bytes())


def test_a_timestamper_may_be_a_coroutine_function(tmp_path: Path, jpeg: Path) -> None:
    called: list[tuple[str, int]] = []

    async def authority(url: str, body: bytes) -> bytes:
        called.append((url, threading.get_ident()))
        return b"not a TimeStampResp"

    definition = baseline_definition(timestamp_url="https://tsa.example/")

    async def scenario() -> None:
        with pytest.raises(C2paError):
            await c2pa.async_sign_file(
                jpeg, tmp_path / "out.jpg", timestamper=authority, **arguments(definition_json=definition)
            )

    run(scenario())
    assert called == [("https://tsa.example/", called[0][1])] and called[0][1] != 0
    assert names(tmp_path) == ["in.jpg"]


def test_a_failing_remote_signer_fails_cleanly_and_spares_the_destination(
    tmp_path: Path, jpeg: Path
) -> None:
    out = tmp_path / "out.jpg"
    out.write_bytes(b"previous")

    async def remote(algorithm: str, data: bytes) -> bytes:
        raise ConnectionError("signing service unreachable")

    async def scenario() -> None:
        with pytest.raises(C2paError) as failure:
            await c2pa.async_sign_file(jpeg, out, **arguments(signer=remote))
        assert isinstance(failure.value.__cause__, ConnectionError)

    run(scenario())
    assert out.read_bytes() == b"previous" and names(tmp_path) == ["in.jpg", "out.jpg"]


def test_async_sign_file_can_replace_its_own_source(tmp_path: Path, jpeg: Path) -> None:
    run(c2pa.async_sign_file(jpeg, jpeg, **arguments()))
    assert trusted(jpeg.read_bytes()) and names(tmp_path) == ["in.jpg"]


@pytest.mark.parametrize(
    "overrides",
    [{"definition_json": "{not json"}, {"certificates": []}, {"algorithm": "rot13"}],
)
def test_bad_settings_fail_before_any_file_is_created(
    tmp_path: Path, jpeg: Path, overrides: dict[str, Any]
) -> None:
    with pytest.raises(C2paError):
        run(c2pa.async_sign_file(jpeg, tmp_path / "out.jpg", **arguments(**overrides)))
    assert names(tmp_path) == ["in.jpg"]


def test_a_missing_source_fails_cleanly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run(c2pa.async_sign_file(tmp_path / "missing.jpg", tmp_path / "out.jpg", **arguments()))
    assert names(tmp_path) == []


def test_concurrent_signings_all_succeed_without_debris(tmp_path: Path, jpeg: Path) -> None:
    async def scenario() -> None:
        await asyncio.gather(
            *(c2pa.async_sign_file(jpeg, tmp_path / f"out{i}.jpg", **arguments()) for i in range(6))
        )

    run(scenario())
    outputs = {(tmp_path / f"out{i}.jpg").read_bytes() for i in range(6)}
    assert len(outputs) == 1 and trusted(outputs.pop())
    assert names(tmp_path) == ["in.jpg"] + [f"out{i}.jpg" for i in range(6)]


def test_cancelling_a_remote_signature_leaves_no_debris_and_spares_the_destination(
    tmp_path: Path, jpeg: Path
) -> None:
    out = tmp_path / "out.jpg"
    out.write_bytes(b"previous")
    gates = Gates("sign")

    async def remote(algorithm: str, data: bytes) -> bytes:
        await gates.gate("sign")
        return es256_sign(data)

    async def scenario() -> None:
        task = asyncio.create_task(c2pa.async_sign_file(jpeg, out, **arguments(signer=remote)))
        await gates.reached("sign")
        assert len(names(tmp_path)) == 3  # the temporary output exists while signing

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert gates.cancelled == ["sign"]
        await eventually(lambda: names(tmp_path) == ["in.jpg", "out.jpg"])

    run(scenario())
    assert out.read_bytes() == b"previous"


def test_a_timeout_bounds_a_hanging_remote_signer(tmp_path: Path, jpeg: Path) -> None:
    async def hanging(algorithm: str, data: bytes) -> bytes:
        await asyncio.Event().wait()
        return b""

    async def scenario() -> None:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.2):
                await c2pa.async_sign_file(jpeg, tmp_path / "out.jpg", **arguments(signer=hanging))
        await eventually(lambda: names(tmp_path) == ["in.jpg"])

    run(scenario())


def test_cancelling_during_a_blocking_signature_keeps_the_temporary_until_it_returns(
    tmp_path: Path, jpeg: Path
) -> None:
    gate = WorkerGate()

    def blocking(algorithm: str, data: bytes) -> bytes:
        gate.block()
        return es256_sign(data)

    async def scenario() -> None:
        task = asyncio.create_task(c2pa.async_sign_file(jpeg, tmp_path / "out.jpg", **arguments(signer=blocking)))
        await gate.reached()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.05)
        assert len(names(tmp_path)) == 2  # the worker is still signing: nothing is removed under it

        gate.release.set()
        await eventually(lambda: names(tmp_path) == ["in.jpg"])

    run(scenario())


def test_cancelling_during_publication_never_leaves_a_partial_destination(
    tmp_path: Path, jpeg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = WorkerGate()
    real_replace = os.replace

    def slow_replace(source: Any, destination: Any) -> None:
        gate.block()
        real_replace(source, destination)

    monkeypatch.setattr(hosts.os, "replace", slow_replace)
    out = tmp_path / "out.jpg"

    async def scenario() -> None:
        task = asyncio.create_task(c2pa.async_sign_file(jpeg, out, **arguments()))
        await gate.reached()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        gate.release.set()
        await eventually(lambda: names(tmp_path) == ["in.jpg", "out.jpg"])

    run(scenario())
    assert trusted(out.read_bytes())  # the rename finished; what is there is complete


def test_a_publication_that_fails_after_cancellation_cleans_up(
    tmp_path: Path, jpeg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = WorkerGate()

    def refusing_replace(source: Any, destination: Any) -> None:
        gate.block()
        raise OSError("cannot rename")

    monkeypatch.setattr(hosts.os, "replace", refusing_replace)
    out = tmp_path / "out.jpg"
    out.write_bytes(b"previous")

    async def scenario() -> None:
        task = asyncio.create_task(c2pa.async_sign_file(jpeg, out, **arguments()))
        await gate.reached()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        gate.release.set()
        await eventually(lambda: names(tmp_path) == ["in.jpg", "out.jpg"])

    run(scenario())
    assert out.read_bytes() == b"previous"


def test_a_failed_publication_is_reported_and_cleaned_up(
    tmp_path: Path, jpeg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(source: Any, destination: Any) -> None:
        raise OSError("cannot rename")

    monkeypatch.setattr(hosts.os, "replace", refuse)
    with pytest.raises(OSError, match="cannot rename"):
        run(c2pa.async_sign_file(jpeg, tmp_path / "out.jpg", **arguments()))
    assert names(tmp_path) == ["in.jpg"]


def test_async_sign_file_does_not_leak_descriptors(tmp_path: Path, jpeg: Path) -> None:
    async def scenario() -> None:
        before = fds()
        for _ in range(20):
            await c2pa.async_sign_file(jpeg, tmp_path / "out.jpg", **arguments())
        await eventually(lambda: fds() <= before)

    run(scenario())
