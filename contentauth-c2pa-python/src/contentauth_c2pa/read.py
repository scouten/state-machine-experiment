"""Reading: a sans-I/O session and its immutable result."""

from enum import IntEnum
from types import TracebackType
from typing import Any

from ._native import ffi, lib
from ._support import (
    Resource,
    c_string,
    check,
    copy_bytes,
    copy_text,
    payload,
    required_string,
    take_string,
)
from .errors import C2paError, ErrorCode
from .vocab import (
    Bytes,
    Failed,
    Length,
    LengthRequest,
    Ocsp,
    OcspRequest,
    ReadRequest,
    Reply,
    Request,
    Step,
    Time,
    TimeRequest,
)


class ValidationState(IntEnum):
    """The overall validation outcome; values are checked against the C header."""

    UNAVAILABLE = -1
    INVALID = 0
    VALID = 1
    TRUSTED = 2


class Reader:
    """An immutable validation result. Everything it reports is copied out of native memory."""

    def __init__(self, raw: Any) -> None:
        self._resource = Resource(raw, lib.c2pa_sm_reader_free)

    def json(self) -> str:
        """The manifest store and its validation status, as c2pa-rs-shaped JSON."""
        with self._resource.use() as raw:
            return required_string(lib.c2pa_sm_reader_json(raw), "reader JSON")

    def validation_state(self) -> ValidationState:
        with self._resource.use() as raw:
            return ValidationState(int(lib.c2pa_sm_reader_validation_state(raw)))

    def active_label(self) -> str | None:
        with self._resource.use() as raw:
            return take_string(lib.c2pa_sm_reader_active_label(raw))

    def is_embedded(self) -> bool:
        with self._resource.use() as raw:
            return bool(lib.c2pa_sm_reader_is_embedded(raw))

    def close(self) -> None:
        """Release the native result; safe to repeat."""
        self._resource.close()

    def __enter__(self) -> "Reader":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def describe(view: Any) -> Request:
    """Copy one native request descriptor into an owned Python request."""
    kind = int(view.kind)
    request_id = int(view.id)
    if kind == lib.C2PA_SM_REQUEST_READ:
        return ReadRequest(request_id, int(view.start), int(view.len))
    if kind == lib.C2PA_SM_REQUEST_LENGTH:
        return LengthRequest(request_id)
    if kind == lib.C2PA_SM_REQUEST_TIME:
        return TimeRequest(request_id)
    if kind == lib.C2PA_SM_REQUEST_OCSP:
        return OcspRequest(
            request_id,
            copy_text(view.url, int(view.url_len)),
            copy_bytes(view.body, int(view.body_len)),
        )
    raise C2paError(ErrorCode.INVALID_ARGUMENT, "", f"unknown read request kind {kind}")


def encode_reply(request_id: int, reply: Reply) -> tuple[Any, Any]:
    """A native reply plus whatever must stay alive until the engine has copied it."""
    native = ffi.new("C2paSmReply *")
    native.id = request_id
    keep: Any
    if isinstance(reply, Bytes | Ocsp):
        native.kind = lib.C2PA_SM_REPLY_BYTES if isinstance(reply, Bytes) else lib.C2PA_SM_REPLY_OCSP
        native.data, native.data_len, keep = payload(reply.data)
    elif isinstance(reply, Failed):
        native.kind = lib.C2PA_SM_REPLY_FAILED
        native.data, native.data_len, keep = payload(reply.message.encode("utf-8"))
    elif isinstance(reply, Length):
        native.kind = lib.C2PA_SM_REPLY_LENGTH
        native.value = reply.value
        keep = None
    elif isinstance(reply, Time):
        native.kind = lib.C2PA_SM_REPLY_TIME
        native.value = reply.seconds
        keep = None
    else:
        raise TypeError(f"{type(reply).__name__} is not a valid reply to a read request")
    return native, keep


class ReadSession:
    """A read of one asset, driven entirely by its caller.

    The session performs no I/O, holds no thread and keeps no pointer into the host. A
    host that stops driving it has stopped it; `close()` (or leaving a `with` block)
    releases the native session deterministically, and a finalizer is only a safety net.
    """

    def __init__(self, format: str, settings_json: str | None = None) -> None:
        """Start reading an asset of `format` (a MIME type or bare extension).

        `settings_json` is c2pa-rs settings JSON; `None` selects the defaults.

        Raises `C2paError` for an unsupported type or invalid settings, before any request.
        """
        slot = ffi.new("C2paSmSession **")
        error = ffi.new("C2paSmError **")
        settings = ffi.NULL if settings_json is None else c_string(settings_json, "settings_json")
        check(lib.c2pa_sm_session_new(c_string(format, "format"), settings, slot, error), error)
        self._resource = Resource(slot[0], lib.c2pa_sm_session_free)

    def advance(self) -> Step:
        """Run the engine as far as it can go without the host, one bounded slice."""
        with self._resource.use() as raw:
            done = ffi.new("int *")
            error = ffi.new("C2paSmError **")
            check(lib.c2pa_sm_session_advance(raw, done, error), error)
            requests: list[Request] = []
            for index in range(int(lib.c2pa_sm_session_request_count(raw))):
                view = ffi.new("C2paSmRequest *")
                if not lib.c2pa_sm_session_request(raw, index, view):
                    raise C2paError(ErrorCode.INVALID_ARGUMENT, "", f"no request at index {index}")
                requests.append(describe(view))
            return Step(done=bool(done[0]), requests=tuple(requests))

    def fulfill(self, request_id: int, reply: Reply) -> None:
        """Report one request's outcome; replies may come in any order and any subset.

        Raises `C2paError` if the id was never issued, was already answered, or `reply` is
        the wrong kind for it; the request stays outstanding and the session stays usable.
        Raises `TypeError` for a reply that is not a read reply at all.
        """
        native, keep = encode_reply(request_id, reply)
        with self._resource.use() as raw:
            error = ffi.new("C2paSmError **")
            check(lib.c2pa_sm_session_fulfill(raw, native, error), error)
        del keep

    def finish(self) -> Reader | None:
        """Consume the session, however it ends.

        Returns `None` when the asset carries no manifest store. Raises `C2paError` if
        the read failed; the session is closed either way.
        """
        with self._resource.consume() as raw:
            result = ffi.new("C2paSmReader **")
            error = ffi.new("C2paSmError **")
            check(lib.c2pa_sm_session_finish(raw, result, error), error)
        return None if result[0] == ffi.NULL else Reader(result[0])

    def close(self) -> None:
        """Cancel the read and release the native session; safe to repeat."""
        self._resource.close()

    def __enter__(self) -> "ReadSession":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
