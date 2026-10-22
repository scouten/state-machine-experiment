import array
import io
import os
from pathlib import Path
import stat
import time

import pytest

from contentauth_c2pa import (
    BuildStream,
    BytesReadHost,
    FileBuildHost,
    MemoryBuildHost,
    StreamBuildHost,
    StreamReadHost,
    hosts,
)

SOURCE, OUTPUT = BuildStream.SOURCE, BuildStream.OUTPUT


def open_fds() -> int:
    return len(os.listdir("/dev/fd"))


# ---- ReadHost ----------------------------------------------------------------


def test_bytes_host_reads_exact_ranges() -> None:
    host = BytesReadHost(bytearray(b"0123456789"))
    assert bytes(host.read(2, 3)) == b"234"
    assert bytes(host.read(10, 0)) == b""
    assert host.length() == 10


def test_bytes_host_reads_are_views_not_copies() -> None:
    data = bytearray(b"abcdef")
    view = BytesReadHost(data).read(1, 3)
    data[1] = ord("X")
    assert bytes(view) == b"Xcd"


@pytest.mark.parametrize("start, length", [(-1, 1), (0, -1), (11, 0), (5, 6), (2**70, 1)])
def test_bytes_host_rejects_out_of_range_reads(start: int, length: int) -> None:
    with pytest.raises(ValueError, match="outside the 10-byte stream"):
        BytesReadHost(bytes(10)).read(start, length)


def test_bytes_host_counts_bytes_not_items() -> None:
    assert BytesReadHost(array.array("I", [1, 2])).length() == 2 * array.array("I").itemsize


def test_bytes_host_rejects_noncontiguous_buffers() -> None:
    with pytest.raises(TypeError):
        BytesReadHost(memoryview(b"abcdef")[::2])


def test_stream_host_reads_any_range_in_any_order() -> None:
    host = StreamReadHost(io.BytesIO(b"0123456789"))
    assert bytes(host.read(6, 3)) == b"678"
    assert bytes(host.read(0, 2)) == b"01"
    assert host.length() == 10
    assert bytes(host.read(2, 2)) == b"23"


@pytest.mark.parametrize("start, length", [(-1, 1), (8, 3), (11, 0)])
def test_stream_host_rejects_out_of_range_reads(start: int, length: int) -> None:
    with pytest.raises(ValueError, match="outside the 10-byte stream"):
        StreamReadHost(io.BytesIO(bytes(10))).read(start, length)


class Trickle(io.BytesIO):
    """Returns one byte per read, as a slow raw stream may."""

    def read(self, size: int | None = -1) -> bytes:
        return super().read(1 if size else 0)


class Truncated(io.BytesIO):
    """Claims more bytes than it can deliver."""

    def read(self, size: int | None = -1) -> bytes:
        return b""


def test_stream_host_gathers_partial_reads() -> None:
    assert bytes(StreamReadHost(Trickle(b"abcdef")).read(1, 4)) == b"bcde"


def test_stream_host_never_acknowledges_a_short_read() -> None:
    with pytest.raises(EOFError, match="0 of 3 bytes"):
        StreamReadHost(Truncated(b"abcdef")).read(0, 3)


def test_stream_host_requires_a_seekable_stream() -> None:
    receive, send = os.pipe()
    try:
        with os.fdopen(receive, "rb") as stream, pytest.raises(ValueError, match="seekable"):
            StreamReadHost(stream)
    finally:
        os.close(send)


def test_clock_defaults_to_the_system_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "time", lambda: 1234.9)
    assert BytesReadHost(b"").now() == 1234
    assert BytesReadHost(b"", clock=lambda: 7).now() == 7


def test_ocsp_without_a_transport_is_an_unreachable_responder() -> None:
    with pytest.raises(ConnectionError, match="no network access"):
        BytesReadHost(b"").ocsp("http://ocsp.example", b"q")
    host = StreamReadHost(io.BytesIO(), ocsp=lambda url, body: url.encode() + body)
    assert host.ocsp("http://x", b"q") == b"http://xq"


# ---- MemoryBuildHost ---------------------------------------------------------


def test_memory_host_writes_extend_and_overwrite() -> None:
    host = MemoryBuildHost(b"source")
    host.write(OUTPUT, 4, b"ab")
    assert host.output == b"\0\0\0\0ab"
    host.write(OUTPUT, 1, b"XY")
    assert host.output == b"\0XY\0ab" and host.length(OUTPUT) == 6
    assert host.length(SOURCE) == 6
    host.write(OUTPUT, 6, b"")
    assert host.length(OUTPUT) == 6


def test_memory_host_reads_both_streams() -> None:
    host = MemoryBuildHost(b"source")
    host.write(OUTPUT, 0, b"output")
    assert bytes(host.read(SOURCE, 1, 3)) == b"our"
    assert bytes(host.read(OUTPUT, 2, 4)) == b"tput"


def test_a_pending_output_read_never_blocks_a_later_write() -> None:
    host = MemoryBuildHost(b"")
    host.write(OUTPUT, 0, b"ab")
    held = host.read(OUTPUT, 0, 2)
    host.write(OUTPUT, 10, b"x")  # would raise BufferError if `held` were a live view
    assert bytes(held) == b"ab"


def test_memory_host_source_is_read_only() -> None:
    with pytest.raises(PermissionError, match="read-only"):
        MemoryBuildHost(b"s").write(SOURCE, 0, b"x")


@pytest.mark.parametrize("stream", list(BuildStream))
def test_memory_host_rejects_out_of_range_reads(stream: BuildStream) -> None:
    with pytest.raises(ValueError, match="outside"):
        MemoryBuildHost(b"").read(stream, 0, 1)


def test_memory_host_rejects_absurd_offsets() -> None:
    with pytest.raises(ValueError, match="outside"):
        MemoryBuildHost(b"").write(OUTPUT, 2**63, b"x")


def test_signer_and_timestamper_are_optional_and_forwarded() -> None:
    bare = MemoryBuildHost(b"")
    with pytest.raises(PermissionError, match="no signer"):
        bare.sign("es256", b"x")
    with pytest.raises(ConnectionError, match="no timestamp"):
        bare.timestamp("https://tsa", b"x")
    host = MemoryBuildHost(
        b"", signer=lambda alg, data: alg.encode() + data, timestamper=lambda url, body: body[::-1]
    )
    assert host.sign("es256", b"-x") == b"es256-x"
    assert host.timestamp("https://tsa", b"abc") == b"cba"


# ---- StreamBuildHost ---------------------------------------------------------


def test_stream_build_host_round_trips_through_its_output() -> None:
    host = StreamBuildHost(io.BytesIO(b"source"), io.BytesIO())
    host.write(OUTPUT, 2, b"ab")
    assert bytes(host.read(OUTPUT, 0, 4)) == b"\0\0ab"
    assert bytes(host.read(SOURCE, 0, 6)) == b"source"
    assert host.length(OUTPUT) == 4 and host.length(SOURCE) == 6


def test_stream_build_host_rejects_unsuitable_streams(tmp_path: Path) -> None:
    shared = io.BytesIO()
    with pytest.raises(ValueError, match="different streams"):
        StreamBuildHost(shared, shared)
    with pytest.raises(ValueError, match="start empty"):
        StreamBuildHost(io.BytesIO(), io.BytesIO(b"x"))
    with open(tmp_path / "out", "wb") as write_only, pytest.raises(ValueError, match="readable"):
        StreamBuildHost(io.BytesIO(), write_only)  # type: ignore[arg-type]
    receive, send = os.pipe()
    try:
        with os.fdopen(receive, "rb") as pipe, pytest.raises(ValueError, match="seekable"):
            StreamBuildHost(pipe, io.BytesIO())
    finally:
        os.close(send)


def test_stream_build_host_source_is_read_only() -> None:
    with pytest.raises(PermissionError):
        StreamBuildHost(io.BytesIO(b"s"), io.BytesIO()).write(SOURCE, 0, b"x")


class Dribble(io.BytesIO):
    """Accepts one byte per write, as a raw stream may."""

    def write(self, data: object) -> int:
        return super().write(bytes(memoryview(data)[:1]))  # type: ignore[arg-type]


class Refusing(io.BytesIO):
    def write(self, data: object) -> int:
        return 0


def test_stream_build_host_completes_partial_writes() -> None:
    output = Dribble()
    host = StreamBuildHost(io.BytesIO(), output)
    host.write(OUTPUT, 0, b"abcd")
    assert output.getvalue() == b"abcd"


def test_stream_build_host_fails_when_the_output_accepts_nothing() -> None:
    with pytest.raises(OSError, match="accepted no bytes"):
        StreamBuildHost(io.BytesIO(), Refusing()).write(OUTPUT, 0, b"abcd")


def test_stream_build_host_reads_are_exact() -> None:
    assert bytes(StreamBuildHost(Trickle(b"abcdef"), io.BytesIO()).read(SOURCE, 1, 4)) == b"bcde"
    with pytest.raises(EOFError):
        StreamBuildHost(Truncated(b"abcdef"), io.BytesIO()).read(SOURCE, 0, 3)
    with pytest.raises(ValueError, match="outside"):
        StreamBuildHost(io.BytesIO(b"ab"), io.BytesIO()).read(SOURCE, 1, 5)


# ---- FileBuildHost -----------------------------------------------------------


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "in.bin"
    path.write_bytes(b"0123456789")
    return path


def names(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def test_file_host_publishes_atomically_and_only_on_request(tmp_path: Path, source: Path) -> None:
    destination = tmp_path / "out.bin"
    with FileBuildHost(source, destination) as host:
        host.write(OUTPUT, 0, b"signed")
        assert bytes(host.read(OUTPUT, 0, 6)) == b"signed"
        assert not destination.exists()
        listing = names(tmp_path)  # the source and the temporary, but no destination yet
        assert listing[1] == "in.bin" and listing[0].startswith(".out.bin.")
        host.publish()
        assert destination.read_bytes() == b"signed"
    assert names(tmp_path) == ["in.bin", "out.bin"]


def test_unpublished_output_leaves_no_debris_and_spares_the_destination(
    tmp_path: Path, source: Path
) -> None:
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"old")
    with FileBuildHost(source, destination) as host:
        host.write(OUTPUT, 0, b"partial")
    assert destination.read_bytes() == b"old"
    assert names(tmp_path) == ["in.bin", "out.bin"]


def test_temporary_files_are_exclusive_and_unpredictable(tmp_path: Path, source: Path) -> None:
    destination = tmp_path / "out.bin"
    with FileBuildHost(source, destination) as first, FileBuildHost(source, destination) as second:
        temporaries = [n for n in names(tmp_path) if n.startswith(".out.bin.")]
        assert len(temporaries) == 2 and temporaries[0] != temporaries[1]
        first.write(OUTPUT, 0, b"first")
        second.write(OUTPUT, 0, b"second")
        first.publish()
    assert destination.read_bytes() == b"first"


def test_output_takes_the_sources_permissions(tmp_path: Path, source: Path) -> None:
    source.chmod(0o640)
    destination = tmp_path / "out.bin"
    with FileBuildHost(source, destination) as host:
        host.publish()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o640


def test_published_destination_replaces_what_was_there(tmp_path: Path, source: Path) -> None:
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"old")
    with FileBuildHost(source, destination) as host:
        host.write(OUTPUT, 0, b"new")
        host.publish()
    assert destination.read_bytes() == b"new"


def test_a_symlink_destination_is_replaced_not_followed(tmp_path: Path, source: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    destination = tmp_path / "link.bin"
    destination.symlink_to(target)
    with FileBuildHost(source, destination) as host:
        host.write(OUTPUT, 0, b"new")
        host.publish()
    assert target.read_bytes() == b"target"
    assert not destination.is_symlink() and destination.read_bytes() == b"new"


def test_file_host_reads_and_writes_are_exact(tmp_path: Path, source: Path) -> None:
    with FileBuildHost(source, tmp_path / "out.bin") as host:
        assert bytes(host.read(SOURCE, 3, 4)) == b"3456"
        assert host.length(SOURCE) == 10 and host.length(OUTPUT) == 0
        host.write(OUTPUT, 4, b"ab")
        assert host.length(OUTPUT) == 6
        assert bytes(host.read(OUTPUT, 3, 3)) == b"\0ab"
        with pytest.raises(ValueError, match="outside"):
            host.read(SOURCE, 8, 5)
        with pytest.raises(PermissionError):
            host.write(SOURCE, 0, b"x")


def test_file_host_completes_short_pwrite_and_pread(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_pwrite, real_pread = os.pwrite, os.pread
    monkeypatch.setattr(hosts.os, "pwrite", lambda fd, data, at: real_pwrite(fd, bytes(data)[:2], at))
    monkeypatch.setattr(hosts.os, "pread", lambda fd, n, at: real_pread(fd, min(n, 3), at))
    with FileBuildHost(source, tmp_path / "out.bin") as host:
        host.write(OUTPUT, 0, b"abcdefg")
        assert bytes(host.read(OUTPUT, 0, 7)) == b"abcdefg"
        assert bytes(host.read(SOURCE, 0, 10)) == b"0123456789"


def test_file_host_fails_when_a_write_makes_no_progress(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hosts.os, "pwrite", lambda fd, data, at: 0)
    with FileBuildHost(source, tmp_path / "out.bin") as host:
        with pytest.raises(OSError, match="accepted no bytes"):
            host.write(OUTPUT, 0, b"x")


def test_file_host_detects_a_file_truncated_under_it(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hosts.os, "pread", lambda fd, n, at: b"")
    with FileBuildHost(source, tmp_path / "out.bin") as host:
        with pytest.raises(EOFError, match="0 of 4 bytes"):
            host.read(SOURCE, 0, 4)


def test_only_regular_files_have_a_length(tmp_path: Path) -> None:
    with FileBuildHost(tmp_path, tmp_path / "out.bin") as host:  # a directory as the source
        with pytest.raises(OSError, match="not a regular file"):
            host.length(SOURCE)


def test_close_is_idempotent_and_ends_publication(tmp_path: Path, source: Path) -> None:
    host = FileBuildHost(source, tmp_path / "out.bin")
    descriptors = open_fds()
    host.close()
    host.close()
    assert open_fds() == descriptors - 2
    with pytest.raises(ValueError, match="closed"):
        host.publish()
    assert names(tmp_path) == ["in.bin"]


def test_failed_publication_cleans_up_and_spares_the_destination(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"old")

    def refuse(*arguments: object) -> None:
        raise OSError("cannot rename")

    monkeypatch.setattr(hosts.os, "replace", refuse)
    with pytest.raises(OSError, match="cannot rename"):
        with FileBuildHost(source, destination) as host:
            host.publish()
    assert destination.read_bytes() == b"old"
    assert names(tmp_path) == ["in.bin", "out.bin"]


def test_missing_source_fails_before_creating_anything(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        FileBuildHost(tmp_path / "missing", tmp_path / "out.bin")
    assert names(tmp_path) == []


def test_missing_destination_directory_does_not_leak_the_source(
    tmp_path: Path, source: Path
) -> None:
    descriptors = open_fds()
    with pytest.raises(FileNotFoundError):
        FileBuildHost(source, tmp_path / "missing" / "out.bin")
    assert open_fds() == descriptors


def test_failure_while_preparing_the_output_leaks_nothing(
    tmp_path: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*arguments: object) -> None:
        raise PermissionError("no chmod")

    monkeypatch.setattr(hosts.os, "fchmod", refuse)
    descriptors = open_fds()
    with pytest.raises(PermissionError, match="no chmod"):
        FileBuildHost(source, tmp_path / "out.bin")
    assert open_fds() == descriptors
    assert names(tmp_path) == ["in.bin"]
