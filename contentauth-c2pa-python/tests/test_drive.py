import io
import json
import os
from pathlib import Path
import threading
from typing import Any

import pytest

import contentauth_c2pa as c2pa
from contentauth_c2pa import (
    BuildLengthRequest,
    BuildReadRequest,
    BuildSession,
    BuildStep,
    BuildStream,
    Bytes,
    BytesReadHost,
    C2paError,
    ErrorCode,
    Failed,
    FileBuildHost,
    Length,
    LengthRequest,
    Ocsp,
    OcspRequest,
    ReadRequest,
    ReadSession,
    SignRequest,
    Signature,
    Step,
    StreamBuildHost,
    Time,
    TimeRequest,
    TimestampRequest,
    TimestampResponse,
    ValidationState,
    Written,
    WriteRequest,
    drive,
)
from support import (
    CERTIFICATE,
    JPEG,
    NOW,
    baseline_definition,
    es256_sign,
    trust_settings,
)

SOURCE, OUTPUT = BuildStream.SOURCE, BuildStream.OUTPUT


def signer(algorithm: str, data: bytes) -> bytes:
    assert algorithm == "es256"
    return es256_sign(data)


def memory_host(**overrides: Any) -> c2pa.MemoryBuildHost:
    return c2pa.MemoryBuildHost(JPEG, **{"signer": signer, **overrides})


def new_session(definition: str | None = None) -> BuildSession:
    return BuildSession(definition or baseline_definition(), "image/jpeg", "es256", [CERTIFICATE])


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


# ---- answering requests ------------------------------------------------------


class Recording(c2pa.ReadHost):
    def read(self, start: int, length: int) -> bytes:
        return b"r" * length

    def length(self) -> int:
        return 42

    def now(self) -> int:
        return 99

    def ocsp(self, url: str, body: bytes) -> bytes:
        return url.encode() + body


def test_every_read_request_is_answered_by_its_host_method() -> None:
    host = Recording()
    assert c2pa.answer_read(host, ReadRequest(1, 0, 3)) == Bytes(b"rrr")
    assert c2pa.answer_read(host, LengthRequest(2)) == Length(42)
    assert c2pa.answer_read(host, TimeRequest(3)) == Time(99)
    assert c2pa.answer_read(host, OcspRequest(4, "u", b"b")) == Ocsp(b"ub")


def test_every_build_request_is_answered_by_its_host_method() -> None:
    host = c2pa.MemoryBuildHost(
        b"abcdef", signer=lambda alg, data: b"sig", timestamper=lambda url, body: b"tsr"
    )
    assert c2pa.answer_build(host, BuildReadRequest(1, SOURCE, 1, 3)) == Bytes(memoryview(b"bcd"))
    assert c2pa.answer_build(host, BuildLengthRequest(2, SOURCE)) == Length(6)
    assert c2pa.answer_build(host, WriteRequest(3, OUTPUT, 0, b"xy")) == Written()
    assert host.output == b"xy"
    assert c2pa.answer_build(host, SignRequest(4, "es256", b"d")) == Signature(b"sig")
    assert c2pa.answer_build(host, TimestampRequest(5, "u", b"q")) == TimestampResponse(b"tsr")


class Failing(Recording):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def read(self, start: int, length: int) -> bytes:
        raise self.error


def test_a_host_exception_becomes_a_failed_reply_with_its_message() -> None:
    reply = c2pa.answer_read(Failing(OSError("disk on fire")), ReadRequest(1, 0, 1))
    assert reply == Failed("disk on fire")
    assert c2pa.answer_build(
        c2pa.MemoryBuildHost(b""), SignRequest(1, "es256", b"")
    ) == Failed("no signer is configured")


def test_an_exception_without_a_message_is_named() -> None:
    assert c2pa.answer_read(Failing(KeyError()), ReadRequest(1, 0, 1)) == Failed("KeyError")


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_interrupts_are_not_host_failures(error: type[BaseException]) -> None:
    with pytest.raises(error):
        c2pa.answer_read(Failing(error()), ReadRequest(1, 0, 1))


class Short(Recording):
    def read(self, start: int, length: int) -> bytes:
        return b"r" * (length + 1)


def test_a_host_returning_the_wrong_number_of_bytes_fails_the_request() -> None:
    assert c2pa.answer_read(Short(), ReadRequest(1, 0, 2)) == Failed(
        "the host returned 3 bytes for a read of 2"
    )


# ---- drive_read --------------------------------------------------------------


def test_drive_read_matches_hand_driving() -> None:
    from support import read_asset as by_hand

    expected = by_hand(JPEG)
    assert expected is not None
    with ReadSession("jpeg") as session:
        reader = c2pa.drive_read(session, BytesReadHost(JPEG, clock=lambda: NOW))
    assert reader is not None and reader.json() == expected.json()


def test_drive_read_returns_none_for_an_unsigned_asset() -> None:
    with ReadSession("jpeg") as session:
        assert c2pa.drive_read(session, BytesReadHost(b"\xff\xd8\xff\xd9")) is None


def test_drive_read_reports_a_malformed_asset() -> None:
    with ReadSession("jpeg") as session, pytest.raises(C2paError) as failure:
        c2pa.drive_read(session, BytesReadHost(b"nope"))
    assert failure.value.code is ErrorCode.READ


def test_a_host_failure_is_reported_by_the_engine_not_swallowed() -> None:
    with ReadSession("jpeg") as session, pytest.raises(C2paError) as failure:
        c2pa.drive_read(session, Failing(OSError("disk on fire")))
    assert "disk on fire" in failure.value.message


def test_drive_read_stops_a_session_that_makes_no_progress() -> None:
    stub = Stub(Step(done=False, requests=()))
    with pytest.raises(C2paError, match="reported no new requests") as failure:
        c2pa.drive_read(stub, Recording())  # type: ignore[arg-type]
    assert failure.value.name == "SessionStalled"


def test_drive_read_finishes_as_soon_as_the_session_is_done() -> None:
    stub = Stub(
        Step(done=False, requests=(OcspRequest(5, "u", b"b"), TimeRequest(6))),
        Step(done=True, requests=()),
    )
    assert c2pa.drive_read(stub, Recording()) == "finished"  # type: ignore[arg-type]
    assert stub.fulfilled == [(5, Ocsp(b"ub")), (6, Time(99))]


# ---- drive_build -------------------------------------------------------------


def trusted(asset: bytes) -> bool:
    reader = c2pa.read_asset(asset, "jpeg", trust_settings(), clock=lambda: NOW)
    return reader is not None and reader.validation_state() is ValidationState.TRUSTED


def test_memory_stream_and_file_hosts_produce_the_same_trusted_asset(tmp_path: Path) -> None:
    memory = memory_host()
    memory_report = c2pa.drive_build(new_session(), memory)

    source, sink = io.BytesIO(JPEG), io.BytesIO()
    stream_report = c2pa.drive_build(new_session(), StreamBuildHost(source, sink, signer=signer))

    (tmp_path / "in.jpg").write_bytes(JPEG)
    with FileBuildHost(tmp_path / "in.jpg", tmp_path / "out.jpg", signer=signer) as host:
        file_report = c2pa.drive_build(new_session(), host)
        host.publish()

    assert memory.output == sink.getvalue() == (tmp_path / "out.jpg").read_bytes()
    assert memory_report == stream_report == file_report
    assert trusted(memory.output)


def test_a_failing_signer_fails_the_build_and_names_the_real_cause() -> None:
    boom = RuntimeError("HSM unreachable")

    def broken(algorithm: str, data: bytes) -> bytes:
        raise boom

    with new_session() as session, pytest.raises(C2paError) as failure:
        c2pa.drive_build(session, memory_host(signer=broken))
    assert failure.value.code is ErrorCode.BUILD
    assert failure.value.__cause__ is boom
    assert "HSM unreachable" in str(failure.value)


def test_a_der_signature_fails_the_build() -> None:
    with new_session() as session, pytest.raises(C2paError) as failure:
        c2pa.drive_build(session, memory_host(signer=lambda a, d: es256_sign(d)[:-1]))
    assert failure.value.code is ErrorCode.BUILD
    assert failure.value.__cause__ is None  # the host answered; the engine objected


def test_a_requested_timestamp_needs_a_transport() -> None:
    definition = baseline_definition(timestamp_url="https://tsa.example/")
    with new_session(definition) as session, pytest.raises(C2paError) as failure:
        c2pa.drive_build(session, memory_host())
    assert isinstance(failure.value.__cause__, ConnectionError)


def test_a_garbage_timestamp_response_fails_the_build() -> None:
    definition = baseline_definition(timestamp_url="https://tsa.example/")
    seen: list[tuple[str, bytes]] = []

    def authority(url: str, body: bytes) -> bytes:
        seen.append((url, body))
        return b"not a TimeStampResp"

    with new_session(definition) as session, pytest.raises(C2paError):
        c2pa.drive_build(session, memory_host(timestamper=authority))
    assert seen and seen[0][0] == "https://tsa.example/" and seen[0][1][:1] == b"\x30"


def test_a_write_failure_fails_the_build_and_names_the_real_cause() -> None:
    with new_session() as session, pytest.raises(C2paError) as failure:
        c2pa.drive_build(session, StreamBuildHost(io.BytesIO(JPEG), RefuseWrites(), signer=signer))
    assert isinstance(failure.value.__cause__, OSError)


class RefuseWrites(io.BytesIO):
    def write(self, data: object) -> int:
        return 0


def test_an_engine_failure_with_no_host_failure_has_no_cause() -> None:
    with new_session() as session, pytest.raises(C2paError) as failure:
        c2pa.drive_build(session, c2pa.MemoryBuildHost(b"not a jpeg", signer=signer))
    assert failure.value.__cause__ is None


def test_drive_build_stops_a_session_that_makes_no_progress() -> None:
    stub = Stub(BuildStep(done=False, requests=()))
    with pytest.raises(C2paError, match="reported no new requests"):
        c2pa.drive_build(stub, memory_host())  # type: ignore[arg-type]


def test_drive_build_finishes_as_soon_as_the_session_is_done() -> None:
    stub = Stub(
        BuildStep(done=False, requests=(BuildLengthRequest(1, SOURCE),)),
        BuildStep(done=True, requests=()),
    )
    assert c2pa.drive_build(stub, memory_host()) == "finished"  # type: ignore[arg-type]
    assert stub.fulfilled == [(1, Length(len(JPEG)))]


# ---- read_asset --------------------------------------------------------------


def expected_json() -> str:
    reader = c2pa.read_asset(JPEG, "jpeg", clock=lambda: NOW)
    assert reader is not None
    return reader.json()


@pytest.fixture
def photo(tmp_path: Path) -> Path:
    path = tmp_path / "photo.JPG"
    path.write_bytes(JPEG)
    return path


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview, io.BytesIO])
def test_read_asset_accepts_bytes_like_and_streams(wrap: Any) -> None:
    reader = c2pa.read_asset(wrap(JPEG), "image/jpeg", clock=lambda: NOW)
    assert reader is not None and reader.json() == expected_json()


def test_read_asset_leaves_a_stream_open() -> None:
    stream = io.BytesIO(JPEG)
    assert c2pa.read_asset(stream, "jpeg") is not None
    assert not stream.closed


def test_read_asset_reads_a_path_and_infers_its_format(photo: Path) -> None:
    for source in (photo, str(photo)):
        reader = c2pa.read_asset(source, clock=lambda: NOW)
        assert reader is not None and reader.json() == expected_json()


def test_an_explicit_format_overrides_the_extension(tmp_path: Path) -> None:
    odd = tmp_path / "photo.bin"
    odd.write_bytes(JPEG)
    assert c2pa.read_asset(odd, "image/jpeg") is not None
    with pytest.raises(C2paError) as failure:
        c2pa.read_asset(odd)
    assert failure.value.code is ErrorCode.UNSUPPORTED_TYPE


def test_the_format_cannot_be_guessed_from_nothing(tmp_path: Path) -> None:
    bare = tmp_path / "photo"
    bare.write_bytes(JPEG)
    with pytest.raises(ValueError, match="pass format="):
        c2pa.read_asset(bare)
    with pytest.raises(ValueError, match="format is required"):
        c2pa.read_asset(JPEG)
    with pytest.raises(ValueError, match="format is required"):
        c2pa.read_asset(io.BytesIO(JPEG))


def test_a_missing_file_is_an_ordinary_os_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        c2pa.read_asset(tmp_path / "missing.jpg")


def test_a_bad_format_closes_the_file(photo: Path) -> None:
    descriptors = len(os.listdir("/dev/fd"))
    with pytest.raises(C2paError):
        c2pa.read_asset(photo, "image/xyz")
    assert len(os.listdir("/dev/fd")) == descriptors


def test_read_asset_forwards_settings(photo: Path) -> None:
    with pytest.raises(C2paError) as failure:
        c2pa.read_asset(photo, settings_json="{not json")
    assert failure.value.code is ErrorCode.INVALID_ARGUMENT


def test_read_asset_forwards_the_clock_and_the_ocsp_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Any] = []
    monkeypatch.setattr(drive, "drive_read", lambda session, host: captured.append(host))
    c2pa.read_asset(JPEG, "jpeg", clock=lambda: 7, ocsp=lambda url, body: b"ok")
    c2pa.read_asset(io.BytesIO(JPEG), "jpeg", clock=lambda: 8, ocsp=lambda url, body: b"ok")
    assert [h.now() for h in captured] == [7, 8]
    assert [h.ocsp("u", b"q") for h in captured] == [b"ok", b"ok"]


def test_the_validation_clock_belongs_to_the_caller() -> None:
    asset = memory_host()
    c2pa.drive_build(new_session(), asset)
    early = c2pa.read_asset(asset.output, "jpeg", trust_settings(), clock=lambda: 0)
    assert early is not None and early.validation_state() is not ValidationState.TRUSTED


# ---- sign_file ---------------------------------------------------------------


def sign_arguments(**overrides: Any) -> dict[str, Any]:
    return {
        "definition_json": baseline_definition(),
        "certificates": [CERTIFICATE],
        "signer": signer,
        **overrides,
    }


@pytest.fixture
def jpeg(tmp_path: Path) -> Path:
    path = tmp_path / "in.jpg"
    path.write_bytes(JPEG)
    return path


def names(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def test_sign_file_signs_into_the_destination_and_reads_back_trusted(
    tmp_path: Path, jpeg: Path
) -> None:
    out = tmp_path / "out.jpg"
    report = c2pa.sign_file(jpeg, out, **sign_arguments())
    assert report.manifest and report.exclusions
    assert trusted(out.read_bytes()) and jpeg.read_bytes() == JPEG
    assert names(tmp_path) == ["in.jpg", "out.jpg"]
    reader = c2pa.read_asset(out, settings_json=trust_settings(), clock=lambda: NOW)
    assert reader is not None
    assert json.loads(reader.json())["manifests"][reader.active_label()]["title"] == "baseline.jpg"


def test_sign_file_matches_signing_in_memory(tmp_path: Path, jpeg: Path) -> None:
    memory = memory_host()
    report = c2pa.drive_build(new_session(), memory)
    assert c2pa.sign_file(jpeg, tmp_path / "out.jpg", **sign_arguments()) == report
    assert (tmp_path / "out.jpg").read_bytes() == memory.output


def test_sign_file_can_replace_its_own_source(tmp_path: Path, jpeg: Path) -> None:
    c2pa.sign_file(jpeg, jpeg, **sign_arguments())
    assert jpeg.read_bytes() != JPEG and trusted(jpeg.read_bytes())
    assert names(tmp_path) == ["in.jpg"]


def test_sign_file_takes_an_explicit_format_and_algorithm(tmp_path: Path) -> None:
    source = tmp_path / "in.bin"
    source.write_bytes(JPEG)
    c2pa.sign_file(source, tmp_path / "out.bin", format="jpeg", algorithm="es256", **sign_arguments())
    assert trusted((tmp_path / "out.bin").read_bytes())


def test_sign_file_answers_timestamp_requests_from_the_callback(
    tmp_path: Path, jpeg: Path
) -> None:
    seen: list[str] = []

    def authority(url: str, body: bytes) -> bytes:
        seen.append(url)
        return b"not a TimeStampResp"

    definition = baseline_definition(timestamp_url="https://tsa.example/")
    with pytest.raises(C2paError):
        c2pa.sign_file(
            jpeg, tmp_path / "out.jpg", timestamper=authority, **sign_arguments(definition_json=definition)
        )
    assert seen == ["https://tsa.example/"]


def test_a_failed_signing_spares_an_existing_destination_and_leaves_no_debris(
    tmp_path: Path, jpeg: Path
) -> None:
    out = tmp_path / "out.jpg"
    out.write_bytes(b"previous")

    def broken(algorithm: str, data: bytes) -> bytes:
        raise RuntimeError("HSM unreachable")

    with pytest.raises(C2paError) as failure:
        c2pa.sign_file(jpeg, out, **sign_arguments(signer=broken))
    assert isinstance(failure.value.__cause__, RuntimeError)
    assert out.read_bytes() == b"previous" and names(tmp_path) == ["in.jpg", "out.jpg"]


def test_an_interrupt_while_signing_leaves_no_debris(tmp_path: Path, jpeg: Path) -> None:
    def interrupted(algorithm: str, data: bytes) -> bytes:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        c2pa.sign_file(jpeg, tmp_path / "out.jpg", **sign_arguments(signer=interrupted))
    assert names(tmp_path) == ["in.jpg"]


@pytest.mark.parametrize(
    "overrides",
    [{"definition_json": "{not json"}, {"certificates": []}, {"algorithm": "rot13"}],
)
def test_bad_settings_fail_before_any_file_is_created(
    tmp_path: Path, jpeg: Path, overrides: dict[str, Any]
) -> None:
    with pytest.raises(C2paError):
        c2pa.sign_file(jpeg, tmp_path / "out.jpg", **sign_arguments(**overrides))
    assert names(tmp_path) == ["in.jpg"]


def test_unsupported_and_uninferable_formats_fail_before_any_file_is_created(
    tmp_path: Path,
) -> None:
    for name in ("in.xyz", "in"):
        (tmp_path / name).write_bytes(JPEG)
        with pytest.raises((C2paError, ValueError)):
            c2pa.sign_file(tmp_path / name, tmp_path / "out", **sign_arguments())
    assert names(tmp_path) == ["in", "in.xyz"]


def test_a_missing_source_fails_cleanly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        c2pa.sign_file(tmp_path / "missing.jpg", tmp_path / "out.jpg", **sign_arguments())
    assert names(tmp_path) == []


def test_a_failed_publication_is_reported_and_cleaned_up(
    tmp_path: Path, jpeg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*arguments: object) -> None:
        raise OSError("cannot rename")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(OSError, match="cannot rename"):
        c2pa.sign_file(jpeg, tmp_path / "out.jpg", **sign_arguments())
    assert names(tmp_path) == ["in.jpg"]


def test_a_directory_source_fails_the_build_with_its_cause(tmp_path: Path) -> None:
    with pytest.raises(C2paError) as failure:
        c2pa.sign_file(tmp_path, tmp_path / "out.jpg", format="jpeg", **sign_arguments())
    assert "not a regular file" in str(failure.value.__cause__)
    assert names(tmp_path) == []


def test_concurrent_signings_do_not_interfere(tmp_path: Path, jpeg: Path) -> None:
    results: list[bytes] = []
    errors: list[BaseException] = []

    def work(index: int) -> None:
        try:
            out = tmp_path / f"out{index}.jpg"
            c2pa.sign_file(jpeg, out, **sign_arguments())
            results.append(out.read_bytes())
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors and len(results) == 6 and len(set(results)) == 1
    assert names(tmp_path) == ["in.jpg"] + [f"out{i}.jpg" for i in range(6)]
