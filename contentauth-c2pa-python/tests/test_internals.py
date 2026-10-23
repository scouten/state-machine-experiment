"""The parts of the adapter that real sessions cannot reach deterministically."""

import gc
from typing import Any
from unittest.mock import Mock

import pytest

from contentauth_c2pa import (
    Bytes,
    BuildStream,
    C2paError,
    ClosedError,
    ErrorCode,
    Failed,
    Length,
    LengthRequest,
    Ocsp,
    OcspRequest,
    ReadRequest,
    Reader,
    ReadSession,
    Signature,
    Time,
    TimeRequest,
    TimestampRequest,
    TimestampResponse,
    ValidationState,
    Written,
)
from contentauth_c2pa import build, read
from contentauth_c2pa import _support as support
from contentauth_c2pa._native import ffi, lib
from contentauth_c2pa.vocab import (
    BuildLengthRequest,
    BuildReadRequest,
    SignRequest,
    WriteRequest,
)


class Missing:
    """A `lib` whose request accessor reports no request at any index."""

    def __getattr__(self, name: str) -> Any:
        if name == "c2pa_sm_session_request":
            return lambda *arguments: False
        return getattr(lib, name)


# ---- the Python enums are the header's constants ------------------------------


@pytest.mark.parametrize("member", list(ErrorCode))
def test_error_codes_match_the_header(member: ErrorCode) -> None:
    assert member.value == getattr(lib, f"C2PA_SM_ERR_{member.name}")


def test_error_codes_cover_every_header_error() -> None:
    header = {n for n in dir(lib) if n.startswith("C2PA_SM_ERR_")}
    assert header == {f"C2PA_SM_ERR_{member.name}" for member in ErrorCode}


@pytest.mark.parametrize("member", list(BuildStream))
def test_build_streams_match_the_header(member: BuildStream) -> None:
    assert member.value == getattr(lib, f"C2PA_SM_BUILD_{member.name}")


@pytest.mark.parametrize("member", list(ValidationState))
def test_validation_states_match_the_header(member: ValidationState) -> None:
    assert member.value == getattr(lib, f"C2PA_SM_VALIDATION_{member.name}")


# ---- vocabulary ---------------------------------------------------------------


@pytest.mark.parametrize("value", [-1, 2**63])
def test_length_must_fit_the_wire(value: int) -> None:
    with pytest.raises(ValueError, match="length out of range"):
        Length(value)


@pytest.mark.parametrize("value", [-(2**63) - 1, 2**63])
def test_time_must_fit_the_wire(value: int) -> None:
    with pytest.raises(ValueError, match="time out of range"):
        Time(value)


def test_extreme_representable_values_are_accepted() -> None:
    assert Length(2**63 - 1).value == 2**63 - 1
    assert Time(-(2**63)).seconds == -(2**63)


def test_vocabulary_is_immutable() -> None:
    with pytest.raises(AttributeError):
        Length(1).value = 2  # type: ignore[misc]


# ---- errors -------------------------------------------------------------------


def test_error_message_includes_the_native_name() -> None:
    assert str(C2paError(ErrorCode.READ, "C2pa(Read)", "bad")) == "C2pa(Read): bad"
    assert str(C2paError(ErrorCode.READ, "", "bad")) == "bad"


def test_missing_native_error_is_still_reported() -> None:
    error = support.error_from(7, ffi.new("C2paSmError **"))
    assert error.code == 7 and "status 7" in str(error)


def test_unknown_native_code_is_kept_as_an_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = ffi.new("C2paSmError **")
    status = lib.c2pa_sm_session_new(b"image/xyz", ffi.NULL, ffi.new("C2paSmSession **"), handle)
    assert status == ErrorCode.UNSUPPORTED_TYPE
    wrapped = Mock(wraps=lib)
    wrapped.c2pa_sm_error_code.return_value = 99
    monkeypatch.setattr(support, "lib", wrapped)
    raised = support.error_from(status, handle)
    assert raised.code == 99 and not isinstance(raised.code, ErrorCode)
    assert "unsupported" in raised.message


def test_check_passes_success_through() -> None:
    support.check(lib.C2PA_SM_OK, ffi.new("C2paSmError **"))


# ---- native string and buffer helpers ----------------------------------------


def test_owned_strings_are_decoded_and_null_means_absent() -> None:
    assert support.take_string(ffi.NULL) is None
    with pytest.raises(C2paError, match="no widget"):
        support.required_string(ffi.NULL, "widget")


def test_null_pointer_is_valid_only_with_length_zero() -> None:
    assert support.copy_bytes(ffi.NULL, 0) == b""
    assert support.copy_text(ffi.NULL, 0) == ""
    assert support.copy_bytes(ffi.new("uint8_t[]", b"abc"), 3) == b"abc"


def test_payloads_pin_nonempty_buffers_and_use_null_for_empty() -> None:
    pointer, length, keep = support.payload(b"")
    assert pointer == ffi.NULL and length == 0 and keep is not None
    pointer, length, keep = support.payload(bytearray(b"xyz"))
    assert length == 3 and bytes(ffi.buffer(pointer, length)) == b"xyz"


def test_noncontiguous_buffers_are_rejected() -> None:
    with pytest.raises((BufferError, ValueError, TypeError)):
        support.payload(memoryview(b"abcdef")[::2])


def test_strings_with_nul_are_rejected() -> None:
    with pytest.raises(ValueError, match="what"):
        support.c_string("a\0b", "what")


# ---- resource ownership ------------------------------------------------------


class Owner:
    pass


def test_finalizer_releases_a_leaked_resource_exactly_once() -> None:
    release = Mock()
    owner = Owner()
    resource = support.Resource("handle", release)
    owner.resource = resource  # type: ignore[attr-defined]
    del resource, owner
    gc.collect()
    release.assert_called_once_with("handle")


def test_close_releases_once_and_disarms_the_finalizer() -> None:
    release = Mock()
    resource = support.Resource("handle", release)
    resource.close()
    resource.close()
    del resource
    gc.collect()
    release.assert_called_once_with("handle")


def test_consume_gives_up_ownership_without_releasing() -> None:
    release = Mock()
    resource = support.Resource("handle", release)
    with resource.consume() as raw:
        assert raw == "handle"
    resource.close()
    del resource
    gc.collect()
    release.assert_not_called()
    other = support.Resource("handle", release)
    other.close()
    with pytest.raises(ClosedError):
        with other.consume():
            pass
    with pytest.raises(ClosedError):
        with other.use():
            pass


# ---- read request descriptors and replies ------------------------------------


KEEP: list[Any] = []  # keeps synthetic native buffers alive for the whole test session


def native_request(kind: int, **fields: Any) -> Any:
    view = ffi.new("C2paSmRequest *")
    view.kind = kind
    view.id = 7
    for name, value in fields.items():
        if isinstance(value, bytes):
            holder = ffi.new("uint8_t[]", value)
            KEEP.append(holder)
            setattr(view, name, holder)
            setattr(view, f"{name}_len", len(value))
        else:
            setattr(view, name, value)
    return view


def test_read_requests_are_described_by_kind() -> None:
    assert read.describe(native_request(lib.C2PA_SM_REQUEST_READ, start=3, len=4)) == ReadRequest(7, 3, 4)
    assert read.describe(native_request(lib.C2PA_SM_REQUEST_LENGTH)) == LengthRequest(7)
    assert read.describe(native_request(lib.C2PA_SM_REQUEST_TIME)) == TimeRequest(7)
    ocsp = read.describe(native_request(lib.C2PA_SM_REQUEST_OCSP, url=b"http://ocsp.example", body=b"\x01\x02"))
    assert ocsp == OcspRequest(7, "http://ocsp.example", b"\x01\x02")
    empty = read.describe(native_request(lib.C2PA_SM_REQUEST_OCSP))
    assert empty == OcspRequest(7, "", b"")


def test_unknown_read_request_kind_is_a_protocol_error() -> None:
    with pytest.raises(C2paError, match="unknown read request kind 99"):
        read.describe(native_request(99))


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        (Bytes(b"ab"), lib.C2PA_SM_REPLY_BYTES),
        (Ocsp(b"ab"), lib.C2PA_SM_REPLY_OCSP),
        (Failed("why"), lib.C2PA_SM_REPLY_FAILED),
        (Length(5), lib.C2PA_SM_REPLY_LENGTH),
        (Time(-5), lib.C2PA_SM_REPLY_TIME),
    ],
)
def test_every_read_reply_is_encoded_by_kind(reply: Any, kind: int) -> None:
    native, keep = read.encode_reply(9, reply)
    assert native.kind == kind and native.id == 9
    if hasattr(reply, "data") or isinstance(reply, Failed):
        expected = reply.message.encode() if isinstance(reply, Failed) else bytes(reply.data)
        assert bytes(ffi.buffer(native.data, native.data_len)) == expected
        assert keep is not None
    else:
        assert native.value == (reply.value if isinstance(reply, Length) else reply.seconds)


def test_read_reply_of_the_wrong_vocabulary_is_a_type_error() -> None:
    with pytest.raises(TypeError, match="Written"):
        read.encode_reply(0, Written())  # type: ignore[arg-type]


def test_advance_reports_a_missing_request_instead_of_inventing_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = ReadSession("jpeg")
    monkeypatch.setattr(read, "lib", Missing())
    with pytest.raises(C2paError, match="no request at index 0"):
        session.advance()


# ---- build request descriptors and replies -----------------------------------


def native_build_request(kind: int, **fields: Any) -> Any:
    view = ffi.new("C2paSmBuildRequest *")
    view.kind = kind
    view.id = 7
    for name, value in fields.items():
        if isinstance(value, bytes):
            holder = ffi.new("uint8_t[]", value)
            KEEP.append(holder)
            buffer = getattr(view, name)
            buffer.data = holder
            buffer.len = len(value)
        else:
            setattr(view, name, value)
    return view


def test_build_requests_are_described_by_kind() -> None:
    source, output = lib.C2PA_SM_BUILD_SOURCE, lib.C2PA_SM_BUILD_OUTPUT
    assert build.describe(
        native_build_request(lib.C2PA_SM_BUILD_REQUEST_READ, stream=source, offset=3, len=4)
    ) == BuildReadRequest(7, BuildStream.SOURCE, 3, 4)
    assert build.describe(
        native_build_request(lib.C2PA_SM_BUILD_REQUEST_LENGTH, stream=output)
    ) == BuildLengthRequest(7, BuildStream.OUTPUT)
    assert build.describe(
        native_build_request(lib.C2PA_SM_BUILD_REQUEST_WRITE, stream=output, offset=9, data=b"xyz")
    ) == WriteRequest(7, BuildStream.OUTPUT, 9, b"xyz")
    assert build.describe(
        native_build_request(lib.C2PA_SM_BUILD_REQUEST_SIGN, algorithm=b"es256", data=b"tbs")
    ) == SignRequest(7, "es256", b"tbs")
    assert build.describe(
        native_build_request(lib.C2PA_SM_BUILD_REQUEST_TIMESTAMP, url=b"https://tsa", data=b"q")
    ) == TimestampRequest(7, "https://tsa", b"q")


def test_unknown_build_request_kind_and_stream_are_protocol_errors() -> None:
    with pytest.raises(C2paError, match="unknown build request kind 99"):
        build.describe(native_build_request(99))
    with pytest.raises(C2paError, match="unknown build stream 5"):
        build.describe(native_build_request(lib.C2PA_SM_BUILD_REQUEST_LENGTH, stream=5))


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        (Bytes(b"ab"), lib.C2PA_SM_BUILD_REPLY_BYTES),
        (Signature(b"ab"), lib.C2PA_SM_BUILD_REPLY_SIGNATURE),
        (TimestampResponse(b"ab"), lib.C2PA_SM_BUILD_REPLY_TIMESTAMP),
        (Failed("why"), lib.C2PA_SM_BUILD_REPLY_FAILED),
        (Length(5), lib.C2PA_SM_BUILD_REPLY_LENGTH),
        (Written(), lib.C2PA_SM_BUILD_REPLY_WRITTEN),
    ],
)
def test_every_build_reply_is_encoded_by_kind(reply: Any, kind: int) -> None:
    native, keep = build.encode_reply(9, reply)
    assert native.kind == kind and native.id == 9
    if isinstance(reply, Length):
        assert native.value == 5
    elif isinstance(reply, Written):
        assert native.data.len == 0 and keep is None
    else:
        expected = reply.message.encode() if isinstance(reply, Failed) else bytes(reply.data)
        assert bytes(ffi.buffer(native.data.data, native.data.len)) == expected


def test_build_reply_of_the_wrong_vocabulary_is_a_type_error() -> None:
    with pytest.raises(TypeError, match="Time"):
        build.encode_reply(0, Time(0))  # type: ignore[arg-type]


def test_reader_type_is_exported() -> None:
    assert Reader.__name__ == "Reader"
