"""Blocking hosts: the synchronous answers to a session's requests.

A host owns every resource a session needs (the asset's bytes, the clock, the
network and, for signing, the key and the output) and answers one request at a
time. Subclass `ReadHost` or `BuildHost` for storage this module does not cover.
Every method may raise; the driver turns an exception into a `Failed` reply so the
*engine* decides what the failure means rather than each host reinventing it.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
import contextlib
import os
from pathlib import Path
import stat
import tempfile
import time
from types import TracebackType
from typing import BinaryIO

from .vocab import Buffer, BuildStream

Clock = Callable[[], int]
"""Unix seconds, UTC."""

OcspTransport = Callable[[str, bytes], Buffer]
"""`(url, DER OCSP request) -> response body`."""

Signer = Callable[[str, bytes], Buffer]
"""`(algorithm, COSE Sig_structure) -> signature`; ES256 returns raw 64-byte `r || s`, not DER."""

Timestamper = Callable[[str, bytes], Buffer]
"""`(url, DER TimeStampReq) -> the complete, unmodified DER TimeStampResp`."""


def _check_range(start: int, length: int, limit: int) -> None:
    if start < 0 or length < 0 or start > limit or length > limit - start:
        raise ValueError(f"I/O of {length} bytes at {start} is outside the {limit}-byte stream")


def _gather(fetch: Callable[[int, int], bytes], length: int, what: str) -> Buffer:
    """Collect exactly `length` bytes from a source that may answer with fewer at a time.

    `fetch(done, remaining)` returns the next bytes. A complete first answer is returned as
    it is, because copying every read a second time costs more than the rare short read does.
    """
    chunk = fetch(0, length)
    if len(chunk) == length:
        return chunk
    gathered = bytearray(chunk)
    while len(gathered) < length:
        chunk = fetch(len(gathered), length - len(gathered))
        if not chunk:
            raise EOFError(f"{what} ended after {len(gathered)} of {length} bytes")
        gathered += chunk
    return gathered


# ---- reading -----------------------------------------------------------------


class ReadHost(ABC):
    """Answers a read session's requests about one asset."""

    def __init__(self, *, clock: Clock | None = None, ocsp: OcspTransport | None = None) -> None:
        self._clock = clock
        self._ocsp = ocsp

    @abstractmethod
    def read(self, start: int, length: int) -> Buffer:
        """Return exactly `length` bytes starting at `start`; never a short read."""

    @abstractmethod
    def length(self) -> int:
        """The asset's length in bytes."""

    def now(self) -> int:
        """The wall clock in Unix seconds; a read is a function of the asset and *this*."""
        return int(time.time()) if self._clock is None else self._clock()

    def ocsp(self, url: str, body: bytes) -> Buffer:
        """One OCSP round trip. With no transport the engine sees an unreachable responder."""
        if self._ocsp is None:
            raise ConnectionError("no network access")
        return self._ocsp(url, body)


class BytesReadHost(ReadHost):
    """An asset already in memory. The buffer must not change while it is being read."""

    def __init__(
        self,
        data: Buffer,
        *,
        clock: Clock | None = None,
        ocsp: OcspTransport | None = None,
    ) -> None:
        super().__init__(clock=clock, ocsp=ocsp)
        self._data = memoryview(data).cast("B")

    def read(self, start: int, length: int) -> Buffer:
        _check_range(start, length, len(self._data))
        return self._data[start : start + length]

    def length(self) -> int:
        return len(self._data)


class StreamReadHost(ReadHost):
    """An asset in a seekable binary stream. The stream stays open and owned by the caller."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        clock: Clock | None = None,
        ocsp: OcspTransport | None = None,
    ) -> None:
        super().__init__(clock=clock, ocsp=ocsp)
        if not stream.seekable():
            raise ValueError("the asset stream must be seekable")
        self._stream = stream

    def read(self, start: int, length: int) -> Buffer:
        _check_range(start, length, self.length())
        self._stream.seek(start)
        return _gather(lambda done, remaining: self._stream.read(remaining), length, "the stream")

    def length(self) -> int:
        return self._stream.seek(0, os.SEEK_END)


# ---- signing -----------------------------------------------------------------


class BuildHost(ABC):
    """Answers a build session's requests: a read-only source, an output, a key, a TSA."""

    def __init__(
        self, *, signer: Signer | None = None, timestamper: Timestamper | None = None
    ) -> None:
        self._signer = signer
        self._timestamper = timestamper

    @abstractmethod
    def read(self, stream: BuildStream, start: int, length: int) -> Buffer:
        """Return exactly `length` bytes of `stream` at `start`; never a short read."""

    @abstractmethod
    def length(self, stream: BuildStream) -> int:
        """The current length of `stream`."""

    @abstractmethod
    def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        """Write all of `data` at `offset` so that later reads see it; only OUTPUT is writable."""

    def sign(self, algorithm: str, data: bytes) -> Buffer:
        if self._signer is None:
            raise PermissionError("no signer is configured")
        return self._signer(algorithm, data)

    def timestamp(self, url: str, body: bytes) -> Buffer:
        if self._timestamper is None:
            raise ConnectionError("no timestamp transport is configured")
        return self._timestamper(url, body)


def _require_output(stream: BuildStream) -> None:
    if stream is not BuildStream.OUTPUT:
        raise PermissionError("the source is read-only")


def _remove(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


class MemoryBuildHost(BuildHost):
    """Source and output both in memory; the finished asset is `output`."""

    def __init__(
        self,
        source: Buffer,
        *,
        signer: Signer | None = None,
        timestamper: Timestamper | None = None,
    ) -> None:
        super().__init__(signer=signer, timestamper=timestamper)
        self._source = memoryview(source).cast("B")
        self._output = bytearray()

    @property
    def output(self) -> bytes:
        return bytes(self._output)

    def _stream(self, stream: BuildStream) -> memoryview | bytearray:
        # Reads of the growing output are copies: a live view of it would block later writes.
        return self._source if stream is BuildStream.SOURCE else self._output

    def read(self, stream: BuildStream, start: int, length: int) -> Buffer:
        data = self._stream(stream)
        _check_range(start, length, len(data))
        return data[start : start + length]

    def length(self, stream: BuildStream) -> int:
        return len(self._stream(stream))

    def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        _require_output(stream)
        _check_range(offset, len(data), 2**62)
        self._output.extend(bytes(max(0, offset + len(data) - len(self._output))))
        self._output[offset : offset + len(data)] = data


class StreamBuildHost(BuildHost):
    """Seekable binary streams: a source to read and a separate, empty output to read back."""

    def __init__(
        self,
        source: BinaryIO,
        output: BinaryIO,
        *,
        signer: Signer | None = None,
        timestamper: Timestamper | None = None,
    ) -> None:
        super().__init__(signer=signer, timestamper=timestamper)
        if source is output:
            raise ValueError("the source and the output must be different streams")
        if not (source.seekable() and output.seekable()):
            raise ValueError("the source and output streams must be seekable")
        if not (output.readable() and output.writable()):
            raise ValueError("the output stream must be both readable and writable")
        self._source = source
        self._output = output
        if self.length(BuildStream.OUTPUT) != 0:
            raise ValueError("the output stream must start empty")

    def _stream(self, stream: BuildStream) -> BinaryIO:
        return self._source if stream is BuildStream.SOURCE else self._output

    def read(self, stream: BuildStream, start: int, length: int) -> Buffer:
        _check_range(start, length, self.length(stream))
        source = self._stream(stream)
        source.seek(start)
        return _gather(lambda done, remaining: source.read(remaining), length, "the stream")

    def length(self, stream: BuildStream) -> int:
        return self._stream(stream).seek(0, os.SEEK_END)

    def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        _require_output(stream)
        _check_range(offset, len(data), 2**62)
        self._output.seek(offset)
        pending = memoryview(data)
        while pending:
            written = self._output.write(pending)
            if not written:
                raise OSError("the output stream accepted no bytes")
            pending = pending[written:]
        self._output.flush()


class FileBuildHost(BuildHost):
    """Files on disk, with atomic publication: POSIX only.

    The output is built in a freshly and exclusively created temporary file with an
    unpredictable name beside `destination`, and only `publish()` renames it into
    place. Until then, and whenever the build fails or this host is closed without
    publishing, an existing `destination` is untouched and the temporary file is
    removed, so a failed build never leaves a partial file or any debris.
    The output gets the source file's permission bits. If `destination` is a
    symbolic link, publishing replaces the link itself, not its target.
    """

    def __init__(
        self,
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
        *,
        signer: Signer | None = None,
        timestamper: Timestamper | None = None,
    ) -> None:
        super().__init__(signer=signer, timestamper=timestamper)
        self._destination = Path(destination)
        self._published = False
        self._temporary: str | None = None
        self._source_fd = os.open(source, os.O_RDONLY)
        try:
            self._output_fd, self._temporary = tempfile.mkstemp(
                prefix=f".{self._destination.name}.",
                suffix=".tmp",
                dir=self._destination.parent,
            )
            try:
                os.fchmod(self._output_fd, stat.S_IMODE(os.fstat(self._source_fd).st_mode))
            except BaseException:
                os.close(self._output_fd)
                raise
        except BaseException:
            os.close(self._source_fd)
            if self._temporary is not None:
                _remove(self._temporary)
            raise

    def _descriptor(self, stream: BuildStream) -> int:
        return self._source_fd if stream is BuildStream.SOURCE else self._output_fd

    def read(self, stream: BuildStream, start: int, length: int) -> Buffer:
        _check_range(start, length, self.length(stream))
        descriptor = self._descriptor(stream)
        return _gather(
            lambda done, remaining: os.pread(descriptor, remaining, start + done), length, "the file"
        )

    def length(self, stream: BuildStream) -> int:
        info = os.fstat(self._descriptor(stream))
        if not stat.S_ISREG(info.st_mode):
            raise OSError("the build stream is not a regular file")
        return info.st_size

    def write(self, stream: BuildStream, offset: int, data: bytes) -> None:
        _require_output(stream)
        pending = memoryview(data)
        written_total = 0
        while pending:
            written = os.pwrite(self._output_fd, pending, offset + written_total)
            if not written:
                raise OSError("the output file accepted no bytes")
            written_total += written
            pending = pending[written:]

    def publish(self) -> None:
        """Make the finished output visible at the destination, atomically."""
        if self._temporary is None:
            raise ValueError("the build file host is closed")
        os.fsync(self._output_fd)
        os.replace(self._temporary, self._destination)
        self._published = True

    def close(self) -> None:
        """Release both files and, unless published, remove the temporary output; repeatable."""
        if self._temporary is None:
            return
        os.close(self._source_fd)
        os.close(self._output_fd)
        if not self._published:
            _remove(self._temporary)
        self._temporary = None

    def __enter__(self) -> "FileBuildHost":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
