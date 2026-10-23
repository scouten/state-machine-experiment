"""Private helpers shared by the read and build adapters."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import threading
from typing import Any
import weakref

from ._native import ffi, lib
from .errors import C2paError, ClosedError, ErrorCode
from .vocab import Buffer


def c_string(value: str, what: str) -> Any:
    """A NUL-terminated copy of `value`; an embedded NUL would silently truncate it."""
    encoded = value.encode("utf-8")
    if b"\0" in encoded:
        raise ValueError(f"{what} must not contain a NUL character")
    return ffi.new("char[]", encoded)


def copy_bytes(pointer: Any, length: int) -> bytes:
    """Copy borrowed native memory; a null pointer is valid only with length zero."""
    return b"" if length == 0 else bytes(ffi.buffer(pointer, length))


def copy_text(pointer: Any, length: int) -> str:
    return copy_bytes(pointer, length).decode("utf-8")


def payload(data: Buffer) -> tuple[Any, int, Any]:
    """Pointer, length and keep-alive for a reply payload, which the engine copies."""
    view = memoryview(data)
    if view.nbytes == 0:
        return ffi.NULL, 0, view
    pinned = ffi.from_buffer("const uint8_t[]", view)
    return pinned, view.nbytes, pinned


def error_from(status: int, slot: Any) -> C2paError:
    """Take ownership of the native error in `slot` and describe it."""
    handle = slot[0]
    if handle == ffi.NULL:
        return C2paError(status, "", f"native call failed with status {status}")
    try:
        raw_code = int(lib.c2pa_sm_error_code(handle))
        name = ffi.string(lib.c2pa_sm_error_name(handle)).decode("utf-8")
        message = ffi.string(lib.c2pa_sm_error_message(handle)).decode("utf-8")
    finally:
        lib.c2pa_sm_error_free(handle)
    try:
        code: ErrorCode | int = ErrorCode(raw_code)
    except ValueError:
        code = raw_code
    return C2paError(code, name, message)


def check(status: int, slot: Any) -> None:
    if status != lib.C2PA_SM_OK:
        raise error_from(status, slot)


def take_string(pointer: Any) -> str | None:
    """Decode and free an owned native string; null means absent."""
    if pointer == ffi.NULL:
        return None
    try:
        return str(ffi.string(pointer).decode("utf-8"))
    finally:
        lib.c2pa_sm_string_free(pointer)


def required_string(pointer: Any, what: str) -> str:
    text = take_string(pointer)
    if text is None:
        raise C2paError(ErrorCode.INVALID_ARGUMENT, "", f"native library returned no {what}")
    return text


class Resource:
    """One native handle: serialized access, explicit close, and a finalizer as a safety net.

    The C API requires a host to serialize operations on each handle, so every use
    holds this lock. `consume()` is for operations that take ownership of the handle.
    """

    def __init__(self, raw: Any, release: Callable[[Any], object]) -> None:
        self._raw: Any | None = raw
        self._lock = threading.Lock()
        self._finalizer = weakref.finalize(self, release, raw)

    @contextmanager
    def use(self) -> Iterator[Any]:
        with self._lock:
            yield self._live()

    @contextmanager
    def consume(self) -> Iterator[Any]:
        """Release ownership before the native call, which consumes the handle on every outcome."""
        with self._lock:
            raw = self._live()
            self._raw = None
            self._finalizer.detach()
            yield raw

    def close(self) -> None:
        with self._lock:
            self._raw = None
            self._finalizer()

    def _live(self) -> Any:
        if self._raw is None:
            raise ClosedError("the session or result is closed or already consumed")
        return self._raw
