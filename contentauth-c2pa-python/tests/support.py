"""Shared fixtures and in-memory hosts for driving sessions by hand."""

import base64
from collections.abc import Callable
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from contentauth_c2pa import (
    BuildLengthRequest,
    BuildReadRequest,
    BuildReply,
    BuildRequest,
    BuildSession,
    BuildStream,
    Bytes,
    Failed,
    Length,
    LengthRequest,
    ReadRequest,
    Reader,
    ReadSession,
    Reply,
    Request,
    Signature,
    SignReport,
    SignRequest,
    Time,
    TimeRequest,
    TimestampRequest,
    TimestampResponse,
    Written,
    WriteRequest,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_800_000_000

JPEG = (ROOT / "contentauth-c2pa-reader/tests/fixtures/C.jpg").read_bytes()
CERTIFICATE = (ROOT / "contentauth-c2pa-builder/tests/fixtures/test-signer.der").read_bytes()
_KEY_PEM = (ROOT / "contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem").read_bytes()


def baseline_definition(*, timestamp_url: str | None = None) -> str:
    """The baseline manifest definition, read from the one place that defines it."""
    source = (ROOT / "contentauth-c2pa-sign-baseline/src/definition.rs").read_text()
    match = re.search(r'BASELINE_DEFINITION: &str = r#"(.*?)"#;', source, re.DOTALL)
    assert match is not None
    definition = match.group(1)
    if timestamp_url is None:
        return definition
    return definition.replace("{", f'{{"tsa_url": {json.dumps(timestamp_url)},', 1)


def es256_sign(data: bytes) -> bytes:
    """Raw 64-byte `r || s`, as the engine requires, not DER."""
    key = serialization.load_pem_private_key(_KEY_PEM, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    r, s = decode_dss_signature(
        key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    )
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def trust_settings() -> str:
    """Settings trusting the test signer's certificate as an anchor."""
    body = base64.encodebytes(CERTIFICATE).decode().strip()
    pem = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
    return json.dumps({"trust": {"trust_anchors": pem}})


def answer_read(request: Request, asset: bytes, now: int = NOW) -> Reply:
    if isinstance(request, ReadRequest):
        return Bytes(asset[request.start : request.start + request.len])
    if isinstance(request, LengthRequest):
        return Length(len(asset))
    if isinstance(request, TimeRequest):
        return Time(now)
    return Failed("no network access")


def drive_read(session: ReadSession, asset: bytes, *, now: int = NOW) -> Reader | None:
    """Answer every request at once, as the simplest possible host."""
    while True:
        step = session.advance()
        for request in step.requests:
            session.fulfill(request.id, answer_read(request, asset, now))
        if step.done:
            return session.finish()


def read_asset(
    asset: bytes,
    *,
    format: str = "image/jpeg",
    settings: str | None = None,
    now: int = NOW,
) -> Reader | None:
    return drive_read(ReadSession(format, settings), asset, now=now)


class MemoryBuildHost:
    """A source and an initially empty, readable and writable output, in memory."""

    def __init__(
        self,
        source: bytes = JPEG,
        sign: Callable[[bytes], bytes] | None = es256_sign,
        timestamp: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.source = source
        self.output = bytearray()
        self.sign = sign
        self.timestamp = timestamp
        self.requests: list[BuildRequest] = []

    def _stream(self, stream: BuildStream) -> bytes | bytearray:
        return self.source if stream is BuildStream.SOURCE else self.output

    def answer(self, request: BuildRequest) -> BuildReply:
        self.requests.append(request)
        if isinstance(request, BuildReadRequest):
            data = self._stream(request.stream)
            return Bytes(memoryview(data)[request.start : request.start + request.len])
        if isinstance(request, BuildLengthRequest):
            return Length(len(self._stream(request.stream)))
        if isinstance(request, WriteRequest):
            end = request.offset + len(request.data)
            self.output.extend(bytes(max(0, end - len(self.output))))
            self.output[request.offset : end] = request.data
            return Written()
        if isinstance(request, SignRequest):
            if self.sign is None:
                return Failed("this host has no signing key")
            return Signature(self.sign(request.data))
        assert isinstance(request, TimestampRequest)
        if self.timestamp is None:
            return Failed("this host has no timestamp authority")
        return TimestampResponse(self.timestamp(request.body))


def new_build(definition: str | None = None, **overrides: object) -> BuildSession:
    arguments: dict[str, object] = {
        "definition_json": baseline_definition() if definition is None else definition,
        "format": "image/jpeg",
        "algorithm": "es256",
        "certificates": [CERTIFICATE],
    }
    return BuildSession(**{**arguments, **overrides})  # type: ignore[arg-type]


def drive_build(session: BuildSession, host: MemoryBuildHost) -> SignReport:
    while True:
        step = session.advance()
        for request in step.requests:
            session.fulfill(request.id, host.answer(request))
        if step.done:
            return session.finish()


def sign_asset(
    definition: str | None = None, host: MemoryBuildHost | None = None
) -> tuple[bytes, SignReport]:
    host = host or MemoryBuildHost()
    report = drive_build(new_build(definition), host)
    return bytes(host.output), report
