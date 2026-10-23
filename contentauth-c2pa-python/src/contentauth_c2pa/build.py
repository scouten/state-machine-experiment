"""Signing: a sans-I/O build session. The host keeps its key and every I/O resource."""

from collections.abc import Sequence
from types import TracebackType
from typing import Any

from ._native import ffi, lib
from ._support import Resource, c_string, check, copy_bytes, copy_text, payload
from .errors import C2paError, ErrorCode
from .vocab import (
    Buffer,
    BuildLengthRequest,
    BuildReadRequest,
    BuildReply,
    BuildRequest,
    BuildStep,
    BuildStream,
    Bytes,
    Exclusion,
    Failed,
    Length,
    SignReport,
    Signature,
    SignRequest,
    TimestampRequest,
    TimestampResponse,
    Written,
    WriteRequest,
)


def stream_of(value: int) -> BuildStream:
    try:
        return BuildStream(value)
    except ValueError:
        raise C2paError(ErrorCode.INVALID_ARGUMENT, "", f"unknown build stream {value}") from None


def describe(view: Any) -> BuildRequest:
    """Copy one native request descriptor into an owned Python request."""
    kind = int(view.kind)
    request_id = int(view.id)
    if kind == lib.C2PA_SM_BUILD_REQUEST_READ:
        return BuildReadRequest(
            request_id, stream_of(int(view.stream)), int(view.offset), int(view.len)
        )
    if kind == lib.C2PA_SM_BUILD_REQUEST_LENGTH:
        return BuildLengthRequest(request_id, stream_of(int(view.stream)))
    if kind == lib.C2PA_SM_BUILD_REQUEST_WRITE:
        return WriteRequest(
            request_id,
            stream_of(int(view.stream)),
            int(view.offset),
            copy_bytes(view.data.data, int(view.data.len)),
        )
    if kind == lib.C2PA_SM_BUILD_REQUEST_SIGN:
        return SignRequest(
            request_id,
            copy_text(view.algorithm.data, int(view.algorithm.len)),
            copy_bytes(view.data.data, int(view.data.len)),
        )
    if kind == lib.C2PA_SM_BUILD_REQUEST_TIMESTAMP:
        return TimestampRequest(
            request_id,
            copy_text(view.url.data, int(view.url.len)),
            copy_bytes(view.data.data, int(view.data.len)),
        )
    raise C2paError(ErrorCode.INVALID_ARGUMENT, "", f"unknown build request kind {kind}")


def encode_reply(request_id: int, reply: BuildReply) -> tuple[Any, Any]:
    """A native reply plus whatever must stay alive until the engine has copied it."""
    native = ffi.new("C2paSmBuildReply *")
    native.id = request_id
    keep: Any = None
    if isinstance(reply, Bytes | Signature | TimestampResponse):
        native.kind = {
            Bytes: lib.C2PA_SM_BUILD_REPLY_BYTES,
            Signature: lib.C2PA_SM_BUILD_REPLY_SIGNATURE,
            TimestampResponse: lib.C2PA_SM_BUILD_REPLY_TIMESTAMP,
        }[type(reply)]
        native.data.data, native.data.len, keep = payload(reply.data)
    elif isinstance(reply, Failed):
        native.kind = lib.C2PA_SM_BUILD_REPLY_FAILED
        native.data.data, native.data.len, keep = payload(reply.message.encode("utf-8"))
    elif isinstance(reply, Length):
        native.kind = lib.C2PA_SM_BUILD_REPLY_LENGTH
        native.value = reply.value
    elif isinstance(reply, Written):
        native.kind = lib.C2PA_SM_BUILD_REPLY_WRITTEN
    else:
        raise TypeError(f"{type(reply).__name__} is not a valid reply to a build request")
    return native, keep


class BuildSession:
    """A signing build, driven entirely by its caller.

    The asset is read from and written to host streams through requests, so the session
    never buffers it. The host also answers every signing and timestamp request; no key
    ever reaches the native library. `close()` (or leaving a `with` block) cancels the
    build deterministically, and a finalizer is only a safety net.
    """

    def __init__(
        self,
        definition_json: str,
        format: str,
        algorithm: str,
        certificates: Sequence[Buffer],
    ) -> None:
        """Start a build of an asset of `format`, signed with `algorithm` (e.g. `"es256"`).

        `definition_json` is the baseline manifest definition; `certificates` is the signer's
        nonempty DER chain, leaf first.

        Raises `C2paError` for an unsupported type, a malformed definition or an empty chain.
        """
        pinned = [payload(certificate) for certificate in certificates]
        native_certificates = ffi.new("C2paSmBuffer[]", max(len(pinned), 1))
        for index, (pointer, length, _) in enumerate(pinned):
            native_certificates[index].data = pointer
            native_certificates[index].len = length
        slot = ffi.new("C2paSmBuildSession **")
        error = ffi.new("C2paSmError **")
        check(
            lib.c2pa_sm_build_session_new(
                c_string(definition_json, "definition_json"),
                c_string(format, "format"),
                c_string(algorithm, "algorithm"),
                native_certificates if pinned else ffi.NULL,
                len(pinned),
                slot,
                error,
            ),
            error,
        )
        self._resource = Resource(slot[0], _free_session)

    def advance(self) -> BuildStep:
        """Run the engine as far as it can go; `requests` are new since the last advance."""
        with self._resource.use() as raw:
            done = ffi.new("int *")
            count = ffi.new("uintptr_t *")
            error = ffi.new("C2paSmError **")
            check(lib.c2pa_sm_build_session_advance(raw, done, count, error), error)
            requests: list[BuildRequest] = []
            for index in range(int(count[0])):
                view = ffi.new("C2paSmBuildRequest *")
                check(lib.c2pa_sm_build_session_request(raw, index, view, error), error)
                requests.append(describe(view))
            return BuildStep(done=bool(done[0]), requests=tuple(requests))

    def fulfill(self, request_id: int, reply: BuildReply) -> None:
        """Answer one outstanding request, in any order.

        Raises `C2paError` for an unknown or already answered id or a reply of the wrong
        kind, leaving the request outstanding. Raises `TypeError` for a reply that is not
        a build reply at all.
        """
        native, keep = encode_reply(request_id, reply)
        with self._resource.use() as raw:
            error = ffi.new("C2paSmError **")
            check(lib.c2pa_sm_build_session_fulfill(raw, native, error), error)
        del keep

    def finish(self) -> SignReport:
        """Consume the session, however it ends; raises `C2paError` if the build failed."""
        with self._resource.consume() as raw:
            slot = ffi.new("C2paSmSignReport **")
            error = ffi.new("C2paSmError **")
            check(lib.c2pa_sm_build_session_finish(raw, slot, error), error)
        report = slot[0]
        try:
            view = ffi.new("C2paSmSignReportView *")
            check(lib.c2pa_sm_sign_report_view(report, view, error), error)
            return SignReport(
                manifest=copy_bytes(view.manifest.data, int(view.manifest.len)),
                exclusions=tuple(
                    Exclusion(int(view.exclusions[i].start), int(view.exclusions[i].len))
                    for i in range(int(view.exclusion_count))
                ),
            )
        finally:
            lib.c2pa_sm_sign_report_free(report, ffi.NULL)

    def close(self) -> None:
        """Cancel the build and release the native session; safe to repeat."""
        self._resource.close()

    def __enter__(self) -> "BuildSession":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _free_session(raw: Any) -> None:
    # Freeing reports failures only through an optional error, which cleanup cannot act on.
    lib.c2pa_sm_build_session_free(raw, ffi.NULL)
