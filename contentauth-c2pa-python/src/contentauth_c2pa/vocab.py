"""Owned, plain-data requests and replies exchanged with a session's host.

Requests are copied out of native memory before `advance()` returns, so they
stay valid for as long as the host keeps them.
"""

from dataclasses import dataclass
from enum import IntEnum

Buffer = bytes | bytearray | memoryview

_INT64_MAX = 2**63 - 1


# ---- reading -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReadRequest:
    """Read `len` bytes of the asset starting at `start`; answer with `Bytes`."""

    id: int
    start: int
    len: int


@dataclass(frozen=True, slots=True)
class LengthRequest:
    """Report the asset's length; answer with `Length`."""

    id: int


@dataclass(frozen=True, slots=True)
class TimeRequest:
    """Report the wall clock; answer with `Time`."""

    id: int


@dataclass(frozen=True, slots=True)
class OcspRequest:
    """POST `body` to the OCSP responder at `url`; answer with `Ocsp`."""

    id: int
    url: str
    body: bytes


Request = ReadRequest | LengthRequest | TimeRequest | OcspRequest


# ---- signing -----------------------------------------------------------------


class BuildStream(IntEnum):
    """The streams a signing session addresses; values are checked against the header."""

    SOURCE = 0
    OUTPUT = 1


@dataclass(frozen=True, slots=True)
class BuildReadRequest:
    """Read exactly `len` bytes of `stream` from `start`; answer with `Bytes`."""

    id: int
    stream: BuildStream
    start: int
    len: int


@dataclass(frozen=True, slots=True)
class BuildLengthRequest:
    """Report the length of `stream`; answer with `Length`."""

    id: int
    stream: BuildStream


@dataclass(frozen=True, slots=True)
class WriteRequest:
    """Write every byte of `data` at `offset`; answer with `Written` once it is readable."""

    id: int
    stream: BuildStream
    offset: int
    data: bytes


@dataclass(frozen=True, slots=True)
class SignRequest:
    """Sign the complete COSE Sig_structure in `data`, not a digest; answer with `Signature`."""

    id: int
    algorithm: str
    data: bytes


@dataclass(frozen=True, slots=True)
class TimestampRequest:
    """POST the DER TimeStampReq `body` to `url`; answer with `TimestampResponse`."""

    id: int
    url: str
    body: bytes


BuildRequest = (
    BuildReadRequest | BuildLengthRequest | WriteRequest | SignRequest | TimestampRequest
)


# ---- replies -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Bytes:
    """The requested bytes."""

    data: Buffer


@dataclass(frozen=True, slots=True)
class Length:
    """A stream's length in bytes."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= _INT64_MAX:
            raise ValueError(f"length out of range: {self.value}")


@dataclass(frozen=True, slots=True)
class Time:
    """Unix seconds, UTC."""

    seconds: int

    def __post_init__(self) -> None:
        if not -(2**63) <= self.seconds <= _INT64_MAX:
            raise ValueError(f"time out of range: {self.seconds}")


@dataclass(frozen=True, slots=True)
class Ocsp:
    """The OCSP responder's response body."""

    data: Buffer


@dataclass(frozen=True, slots=True)
class Failed:
    """The host could not answer; the engine decides what that means."""

    message: str


@dataclass(frozen=True, slots=True)
class Written:
    """A write's entire payload is visible to subsequent reads."""


@dataclass(frozen=True, slots=True)
class Signature:
    """A signature over the request's data; ES256 is raw 64-byte `r || s`, not DER."""

    data: Buffer


@dataclass(frozen=True, slots=True)
class TimestampResponse:
    """The unmodified DER TimeStampResp, not just its TimeStampToken."""

    data: Buffer


Reply = Bytes | Length | Time | Ocsp | Failed
BuildReply = Bytes | Length | Written | Signature | TimestampResponse | Failed


# ---- steps and results -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Step:
    """What `ReadSession.advance()` reports.

    `requests` holds only requests that are new since the last advance. An empty
    batch while `done` is false means the session is waiting on earlier ones.
    """

    done: bool
    requests: tuple[Request, ...]


@dataclass(frozen=True, slots=True)
class BuildStep:
    """What `BuildSession.advance()` reports; `requests` are new since the last advance."""

    done: bool
    requests: tuple[BuildRequest, ...]


@dataclass(frozen=True, slots=True)
class Exclusion:
    """A range of the output asset omitted from its hard-binding hash."""

    start: int
    len: int


@dataclass(frozen=True, slots=True)
class SignReport:
    """A completed build; the signed asset is already in the host's output stream."""

    manifest: bytes
    exclusions: tuple[Exclusion, ...]
