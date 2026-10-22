import gc
import json

from contentauth_c2pa import (
    BuildLengthRequest,
    BuildReadRequest,
    BuildSession,
    BuildStream,
    Bytes,
    C2paError,
    ClosedError,
    ErrorCode,
    Failed,
    Length,
    SignRequest,
    Signature,
    TimestampRequest,
    TimestampResponse,
    ValidationState,
    Written,
    WriteRequest,
)
import pytest
from support import (
    CERTIFICATE,
    JPEG,
    NOW,
    MemoryBuildHost,
    baseline_definition,
    drive_build,
    es256_sign,
    new_build,
    read_asset,
    sign_asset,
    trust_settings,
)


def test_signed_asset_reads_back_trusted_with_the_signer_as_anchor() -> None:
    asset, _ = sign_asset()
    reader = read_asset(asset, settings=trust_settings())
    assert reader is not None
    assert reader.validation_state() is ValidationState.TRUSTED
    manifest = json.loads(reader.json())["manifests"][reader.active_label()]
    assert manifest["title"] == "baseline.jpg"
    assert manifest["claim_generator_info"][0]["name"] == "c2pa-sign-baseline"


def test_signed_asset_is_only_valid_without_the_anchor() -> None:
    asset, _ = sign_asset()
    reader = read_asset(asset)
    assert reader is not None and reader.validation_state() is ValidationState.VALID


def test_the_validation_clock_belongs_to_the_host() -> None:
    asset, _ = sign_asset()
    early = read_asset(asset, settings=trust_settings(), now=0)
    assert early is not None and early.validation_state() is not ValidationState.TRUSTED
    on_time = read_asset(asset, settings=trust_settings(), now=NOW)
    assert on_time is not None and on_time.validation_state() is ValidationState.TRUSTED


def test_report_describes_the_manifest_embedded_in_the_output() -> None:
    host = MemoryBuildHost()
    report = drive_build(new_build(), host)
    assert report.manifest and bytes(host.output).count(report.manifest) == 1
    assert report.exclusions
    previous_end = 0
    for exclusion in report.exclusions:
        assert exclusion.len > 0 and exclusion.start >= previous_end
        previous_end = exclusion.start + exclusion.len
    assert previous_end <= len(host.output)


def test_build_never_asks_for_anything_outside_the_protocol() -> None:
    host = MemoryBuildHost()
    drive_build(new_build(), host)
    kinds = {type(request) for request in host.requests}
    assert kinds == {BuildReadRequest, BuildLengthRequest, WriteRequest, SignRequest}
    assert {r.stream for r in host.requests if isinstance(r, BuildLengthRequest)} >= {
        BuildStream.SOURCE
    }
    (signing,) = [r for r in host.requests if isinstance(r, SignRequest)]
    assert signing.algorithm == "es256" and len(signing.data) > 64


def test_requests_are_owned_copies_that_outlive_the_session() -> None:
    host = MemoryBuildHost()
    drive_build(new_build(), host)
    writes = [r for r in host.requests if isinstance(r, WriteRequest)]
    assert writes and all(isinstance(w.data, bytes) and w.data for w in writes)
    assert max(w.offset + len(w.data) for w in writes) == len(host.output)


def test_replies_may_be_any_contiguous_buffer() -> None:
    expected = sign_asset()[0]
    host = MemoryBuildHost()
    answer = host.answer

    def rewrap(request):  # type: ignore[no-untyped-def]
        reply = answer(request)
        if hasattr(reply, "data") and not isinstance(request, WriteRequest):
            return type(reply)(bytearray(reply.data))
        return reply

    host.answer = rewrap  # type: ignore[method-assign]
    drive_build(new_build(), host)
    assert bytes(host.output) == expected


def test_signer_failure_fails_the_build_with_its_message() -> None:
    host = MemoryBuildHost(sign=None)
    with pytest.raises(C2paError) as failure:
        drive_build(new_build(), host)
    assert failure.value.code is ErrorCode.BUILD
    assert "no signing key" in failure.value.message


def test_a_der_signature_is_rejected_not_silently_embedded() -> None:
    with pytest.raises(C2paError) as failure:
        drive_build(new_build(), MemoryBuildHost(sign=lambda data: es256_sign(data)[:-1]))
    assert failure.value.code is ErrorCode.BUILD


def test_an_invalid_signature_builds_but_does_not_validate() -> None:
    host = MemoryBuildHost(sign=lambda data: bytes(64))
    drive_build(new_build(), host)
    reader = read_asset(bytes(host.output), settings=trust_settings())
    assert reader is not None and reader.validation_state() is ValidationState.INVALID


def test_timestamp_requests_carry_the_url_and_encoded_query() -> None:
    host = MemoryBuildHost()
    definition = baseline_definition(timestamp_url="https://tsa.example/")
    with pytest.raises(C2paError) as failure:
        drive_build(new_build(definition), host)
    assert failure.value.code is ErrorCode.BUILD
    (request,) = [r for r in host.requests if isinstance(r, TimestampRequest)]
    assert request.url == "https://tsa.example/" and request.body[:1] == b"\x30"


def test_garbage_timestamp_response_fails_the_build() -> None:
    host = MemoryBuildHost(timestamp=lambda body: b"not a TimeStampResp")
    definition = baseline_definition(timestamp_url="https://tsa.example/")
    with pytest.raises(C2paError):
        drive_build(new_build(definition), host)


def test_an_untimestamped_build_never_asks_for_a_timestamp() -> None:
    host = MemoryBuildHost(timestamp=lambda body: pytest.fail("unexpected timestamp"))
    drive_build(new_build(), host)


def test_write_failure_fails_the_build() -> None:
    host = MemoryBuildHost()
    session = new_build()
    with pytest.raises(C2paError):
        while True:
            step = session.advance()
            for request in step.requests:
                reply = Failed("disk full") if isinstance(request, WriteRequest) else host.answer(request)
                session.fulfill(request.id, reply)
            if step.done:
                session.finish()


def test_empty_batch_while_waiting_is_not_completion() -> None:
    with new_build() as session:
        first = session.advance()
        assert not first.done and first.requests
        again = session.advance()
        assert not again.done and again.requests == ()


def test_replies_may_arrive_late_in_any_order_and_any_subset() -> None:
    expected = sign_asset()[0]
    host = MemoryBuildHost()
    session = new_build()
    held = []
    for _ in range(10_000):
        step = session.advance()
        held.extend(step.requests)
        if held and (len(held) > 1 or not step.requests):
            request = held.pop()
            session.fulfill(request.id, host.answer(request))
        if step.done:
            break
    session.finish()
    assert bytes(host.output) == expected


def test_unknown_id_and_wrong_reply_kind_leave_the_request_outstanding() -> None:
    host = MemoryBuildHost()
    session = new_build()
    (request, *_) = session.advance().requests
    with pytest.raises(C2paError) as unknown:
        session.fulfill(999_999, Length(0))
    assert unknown.value.code is ErrorCode.INVALID_ARGUMENT
    with pytest.raises(C2paError):
        session.fulfill(request.id, Written())
    session.fulfill(request.id, host.answer(request))


@pytest.mark.parametrize("reply", [object(), b"raw", None])
def test_non_replies_are_a_type_error(reply: object) -> None:
    session = new_build()
    (request, *_) = session.advance().requests
    with pytest.raises(TypeError, match="not a valid reply"):
        session.fulfill(request.id, reply)  # type: ignore[arg-type]


def test_read_replies_are_not_build_replies() -> None:
    from contentauth_c2pa import Time

    session = new_build()
    (request, *_) = session.advance().requests
    with pytest.raises(TypeError):
        session.fulfill(request.id, Time(0))  # type: ignore[arg-type]


def test_wrong_reply_kinds_are_all_rejected_and_the_request_stays_outstanding() -> None:
    session = new_build()
    (request, *_) = session.advance().requests
    assert isinstance(request, BuildLengthRequest)
    for reply in (Signature(b"x"), Written(), Bytes(b"z")):
        with pytest.raises(C2paError):
            session.fulfill(request.id, reply)
    session.fulfill(request.id, Length(len(JPEG)))


def test_early_finish_fails_and_consumes_the_session() -> None:
    session = new_build()
    with pytest.raises(C2paError):
        session.finish()
    with pytest.raises(ClosedError):
        session.advance()


def test_finished_session_cannot_be_used_again() -> None:
    session = new_build()
    drive_build(session, MemoryBuildHost())
    for use in (session.advance, session.finish, lambda: session.fulfill(0, Written())):
        with pytest.raises(ClosedError):
            use()
    session.close()


def test_close_cancels_and_is_idempotent() -> None:
    session = new_build()
    session.advance()
    session.close()
    session.close()
    with pytest.raises(ClosedError):
        session.advance()


def test_context_manager_closes_on_error() -> None:
    with pytest.raises(KeyError):
        with new_build() as session:
            raise KeyError
    with pytest.raises(ClosedError):
        session.advance()


def test_dropped_session_is_released_by_the_finalizer() -> None:
    session = new_build()
    session.advance()
    del session
    gc.collect()


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"certificates": []}, ErrorCode.INVALID_ARGUMENT),
        ({"certificates": [b""]}, ErrorCode.INVALID_ARGUMENT),
        ({"format": "image/xyz"}, ErrorCode.UNSUPPORTED_TYPE),
        ({"definition_json": "{not json"}, None),
        ({"algorithm": "rot13"}, None),
    ],
)
def test_constructor_rejects_bad_input_before_any_request(
    overrides: dict[str, object], code: ErrorCode | None
) -> None:
    with pytest.raises(C2paError) as failure:
        new_build(**overrides)
    if code is not None:
        assert failure.value.code is code


@pytest.mark.parametrize("field", ["definition_json", "format", "algorithm"])
def test_embedded_nul_is_rejected_not_truncated(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        new_build(**{field: "a\0b"})


def test_certificate_chain_accepts_any_buffer_type() -> None:
    for chain in ([bytearray(CERTIFICATE)], [memoryview(CERTIFICATE)], (CERTIFICATE,)):
        BuildSession(baseline_definition(), "image/jpeg", "es256", chain).close()


def test_source_is_never_modified() -> None:
    host = MemoryBuildHost()
    drive_build(new_build(), host)
    assert host.source == JPEG
