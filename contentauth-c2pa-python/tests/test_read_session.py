import gc
import json
import threading

from contentauth_c2pa import (
    Bytes,
    C2paError,
    ClosedError,
    ErrorCode,
    Failed,
    Length,
    LengthRequest,
    ReadRequest,
    ReadSession,
    TimeRequest,
    Time,
    ValidationState,
)
import pytest
from support import JPEG, NOW, answer_read, drive_read, read_asset, trust_settings


def test_signed_asset_reads_as_valid_without_trust() -> None:
    with read_asset(JPEG) as reader:  # type: ignore[union-attr]
        assert reader.validation_state() is ValidationState.VALID
        assert reader.is_embedded()
        label = reader.active_label()
        assert label is not None and label.startswith("contentauth:urn:uuid:")
        assert json.loads(reader.json())["active_manifest"] == label


def test_unsigned_asset_finishes_without_a_reader() -> None:
    assert read_asset(b"\xff\xd8\xff\xd9") is None


def test_malformed_asset_is_an_error_not_unsigned() -> None:
    with pytest.raises(C2paError) as failure:
        read_asset(b"not a jpeg")
    assert failure.value.code is ErrorCode.READ
    assert "SOI" in failure.value.message
    assert failure.value.name.startswith("C2pa(")


def test_unsupported_type_fails_before_any_request() -> None:
    with pytest.raises(C2paError) as failure:
        ReadSession("image/xyz")
    assert failure.value.code is ErrorCode.UNSUPPORTED_TYPE


def test_invalid_settings_fail_before_any_request() -> None:
    with pytest.raises(C2paError) as failure:
        ReadSession("image/jpeg", "{not json")
    assert failure.value.code is ErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("field", ["format", "settings_json"])
def test_embedded_nul_is_rejected_not_truncated(field: str) -> None:
    arguments = {"format": "image/jpeg", "settings_json": "{}"}
    arguments[field] = "a\0b"
    with pytest.raises(ValueError, match=field):
        ReadSession(**arguments)


def test_first_advance_reports_new_requests_and_repeats_none() -> None:
    with ReadSession("jpeg") as session:
        first = session.advance()
        assert not first.done and first.requests == (LengthRequest(id=first.requests[0].id),)
        assert session.advance().requests == ()
        assert not session.advance().done


def test_requests_outlive_the_session_that_issued_them() -> None:
    session = ReadSession("jpeg")
    (request,) = session.advance().requests
    session.close()
    assert isinstance(request, LengthRequest)


def test_replies_may_arrive_late_in_any_order_and_any_subset() -> None:
    expected = read_asset(JPEG, settings=trust_settings())
    assert expected is not None
    session = ReadSession("jpeg", trust_settings())
    held = []
    for _ in range(10_000):
        step = session.advance()
        held.extend(step.requests)
        if held and (len(held) > 1 or not step.requests):
            request = held.pop()  # newest first, leaving older requests outstanding
            session.fulfill(request.id, answer_read(request, JPEG))
        if step.done:
            break
    reader = session.finish()
    assert reader is not None and reader.json() == expected.json()


def test_unknown_request_id_is_rejected_and_the_session_stays_usable() -> None:
    session = ReadSession("jpeg")
    (request,) = session.advance().requests
    with pytest.raises(C2paError) as failure:
        session.fulfill(999_999, Length(len(JPEG)))
    assert failure.value.code is ErrorCode.INVALID_ARGUMENT
    session.fulfill(request.id, Length(len(JPEG)))
    assert session.advance().requests


def test_wrong_reply_kind_leaves_the_request_outstanding() -> None:
    session = ReadSession("jpeg")
    (request,) = session.advance().requests
    with pytest.raises(C2paError) as failure:
        session.fulfill(request.id, Time(NOW))
    assert failure.value.code is ErrorCode.READ
    session.fulfill(request.id, Length(len(JPEG)))
    assert session.advance().requests


def test_answered_request_cannot_be_answered_again() -> None:
    session = ReadSession("jpeg")
    (request,) = session.advance().requests
    session.fulfill(request.id, Length(len(JPEG)))
    with pytest.raises(C2paError):
        session.fulfill(request.id, Length(len(JPEG)))


@pytest.mark.parametrize("reply", [object(), "bytes", 3, None])
def test_non_replies_are_a_type_error(reply: object) -> None:
    session = ReadSession("jpeg")
    (request,) = session.advance().requests
    with pytest.raises(TypeError, match="not a valid reply"):
        session.fulfill(request.id, reply)  # type: ignore[arg-type]
    session.fulfill(request.id, Length(1))


def test_build_replies_are_not_read_replies() -> None:
    from contentauth_c2pa import Written

    session = ReadSession("jpeg")
    (request,) = session.advance().requests
    with pytest.raises(TypeError):
        session.fulfill(request.id, Written())  # type: ignore[arg-type]


def test_reply_payloads_accept_any_contiguous_buffer() -> None:
    for wrap in (bytes, bytearray, memoryview):
        reader = drive_read(
            ReadSession("jpeg"), JPEG
        )  # baseline answer uses bytes; now rewrap each read
        assert reader is not None
        session = ReadSession("jpeg")
        while True:
            step = session.advance()
            for request in step.requests:
                reply = answer_read(request, JPEG)
                if isinstance(reply, Bytes):
                    reply = Bytes(wrap(reply.data))
                session.fulfill(request.id, reply)
            if step.done:
                break
        rebuilt = session.finish()
        assert rebuilt is not None and rebuilt.json() == reader.json()


def test_empty_bytes_reply_is_a_valid_payload() -> None:
    session = ReadSession("jpeg")
    (length,) = session.advance().requests
    session.fulfill(length.id, Length(len(JPEG)))
    request = next(r for r in session.advance().requests if isinstance(r, ReadRequest))
    session.fulfill(request.id, Bytes(b""))
    with pytest.raises(C2paError):
        while True:
            step = session.advance()
            for pending in step.requests:
                session.fulfill(pending.id, answer_read(pending, JPEG))
            if step.done:
                session.finish()
                break


def test_host_failure_fails_the_read_with_its_message() -> None:
    session = ReadSession("jpeg")
    (length,) = session.advance().requests
    session.fulfill(length.id, Length(len(JPEG)))
    with pytest.raises(C2paError) as failure:
        while True:
            step = session.advance()
            for request in step.requests:
                session.fulfill(request.id, Failed("disk on fire"))
            if step.done:
                session.finish()
    assert failure.value.code is ErrorCode.READ
    assert "disk on fire" in failure.value.message


def test_clock_is_asked_of_the_host() -> None:
    session = ReadSession("jpeg")
    seen = []
    while True:
        step = session.advance()
        for request in step.requests:
            seen.append(request)
            session.fulfill(request.id, answer_read(request, JPEG))
        if step.done:
            break
    assert session.finish() is not None
    assert any(isinstance(request, TimeRequest) for request in seen)


def test_early_finish_fails_and_consumes_the_session() -> None:
    session = ReadSession("jpeg")
    with pytest.raises(C2paError) as failure:
        session.finish()
    assert failure.value.code is ErrorCode.READ
    with pytest.raises(ClosedError):
        session.advance()


def test_finished_session_cannot_be_used_again() -> None:
    session = ReadSession("jpeg")
    drive_read(session, JPEG)
    for use in (session.advance, session.finish, lambda: session.fulfill(0, Length(0))):
        with pytest.raises(ClosedError):
            use()
    session.close()  # a no-op, not an error


def test_close_is_idempotent_and_cancels() -> None:
    session = ReadSession("jpeg")
    session.advance()
    session.close()
    session.close()
    with pytest.raises(ClosedError):
        session.advance()


def test_context_manager_closes_on_error() -> None:
    with pytest.raises(KeyError):
        with ReadSession("jpeg") as session:
            raise KeyError
    with pytest.raises(ClosedError):
        session.advance()


def test_reader_results_survive_their_session() -> None:
    session = ReadSession("jpeg")
    reader = drive_read(session, JPEG)
    assert reader is not None
    session.close()
    assert reader.json()
    reader.close()
    reader.close()
    for use in (reader.json, reader.validation_state, reader.active_label, reader.is_embedded):
        with pytest.raises(ClosedError):
            use()


def test_dropped_session_is_released_by_the_finalizer() -> None:
    session = ReadSession("jpeg")
    session.advance()
    del session
    gc.collect()


def test_sessions_on_separate_threads_do_not_interfere() -> None:
    results: list[str] = []

    def work() -> None:
        reader = read_asset(JPEG)
        assert reader is not None
        results.append(reader.json())

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 8 and len(set(results)) == 1


def test_one_session_is_serialized_across_threads() -> None:
    session = ReadSession("jpeg")
    batches = []

    def work() -> None:
        for _ in range(50):
            batches.append(session.advance().requests)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(len(batch) for batch in batches) == 1  # the one request is reported once
