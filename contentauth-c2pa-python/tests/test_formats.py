"""TIFF through the binding: the second container format, with a different shape to JPEG.

The store goes in a new trailing IFD, so nothing already in the file moves, and the hard
binding excludes two separate ranges. These tests build tiny TIFFs of every layout the
handler accepts (either byte order, classic and BigTIFF) and take them through the same
read and sign paths as the JPEG tests, including the file helpers choosing a format from
a path's extension.
"""

import io
from pathlib import Path
import struct

import pytest

import contentauth_c2pa as c2pa
from contentauth_c2pa import (
    BuildSession,
    C2paError,
    ErrorCode,
    FileBuildHost,
    MemoryBuildHost,
    StreamBuildHost,
    ValidationState,
)
from async_support import run
from support import CERTIFICATE, NOW, baseline_definition, es256_sign, trust_settings

PIXELS = 16
LAYOUTS = [("<", False), (">", False), ("<", True), (">", True)]
IDS = ["little", "big", "little-bigtiff", "big-bigtiff"]


def tiff(order: str, big: bool) -> bytes:
    """One IFD (width, strip offset, strip size) followed by its pixel data."""
    word = 8 if big else 4

    def entry(tag: int, kind: int, value: int) -> bytes:
        field = struct.pack(order + ("H" if kind == 3 else "I"), value).ljust(word, b"\0")
        count = struct.pack(order + ("Q" if big else "I"), 1)
        return struct.pack(order + "HH", tag, kind) + count + field

    if big:
        header = (b"II" if order == "<" else b"MM") + struct.pack(order + "HHHQ", 43, 8, 0, 16)
        count, link, entry_len = struct.pack(order + "Q", 3), struct.pack(order + "Q", 0), 20
    else:
        header = (b"II" if order == "<" else b"MM") + struct.pack(order + "HI", 42, 8)
        count, link, entry_len = struct.pack(order + "H", 3), struct.pack(order + "I", 0), 12
    pixels = len(header) + len(count) + 3 * entry_len + len(link)
    entries = [entry(256, 3, PIXELS), entry(273, 4, pixels), entry(279, 4, PIXELS)]
    return header + count + b"".join(entries) + link + bytes(range(0xA0, 0xA0 + PIXELS))


def signer(algorithm: str, data: bytes) -> bytes:
    assert algorithm == "es256"
    return es256_sign(data)


def sign(asset: bytes, format: str = "tiff") -> bytes:
    host = MemoryBuildHost(asset, signer=signer)
    with BuildSession(baseline_definition(), format, "es256", [CERTIFICATE]) as session:
        c2pa.drive_build(session, host)
    return host.output


def state(asset: bytes, format: str = "tiff") -> ValidationState:
    reader = c2pa.read_asset(asset, format, trust_settings(), clock=lambda: NOW)
    assert reader is not None
    return reader.validation_state()


@pytest.mark.parametrize(("order", "big"), LAYOUTS, ids=IDS)
def test_an_unsigned_tiff_has_no_content_credentials(order: str, big: bool) -> None:
    assert c2pa.read_asset(tiff(order, big), "tiff") is None


@pytest.mark.parametrize(("order", "big"), LAYOUTS, ids=IDS)
def test_a_signed_tiff_reads_back_trusted_and_only_appends(order: str, big: bool) -> None:
    source = tiff(order, big)
    signed = sign(source)
    assert signed[: len(source)] != source  # the one next-IFD pointer is rewritten...
    assert signed[len(source) - PIXELS : len(source)] == source[-PIXELS:]  # ...the pixels stay
    assert len(signed) > len(source)
    assert state(signed) is ValidationState.TRUSTED


@pytest.mark.parametrize(("order", "big"), LAYOUTS, ids=IDS)
def test_a_tampered_tiff_is_invalid(order: str, big: bool) -> None:
    signed = bytearray(sign(tiff(order, big)))
    signed[len(tiff(order, big)) - 1] ^= 0xFF  # a pixel byte, covered by the hard binding
    assert state(bytes(signed)) is ValidationState.INVALID


@pytest.mark.parametrize("name", ["tiff", "tif", "image/tiff", "dng", "TIFF"])
def test_every_spelling_of_the_format_is_accepted(name: str) -> None:
    assert state(sign(tiff("<", False), name), name) is ValidationState.TRUSTED


def test_the_format_must_match_the_asset() -> None:
    with pytest.raises(C2paError) as failure:
        sign(tiff("<", False), "jpeg")
    assert failure.value.code is ErrorCode.BUILD
    with pytest.raises(C2paError):
        c2pa.read_asset(tiff("<", False), "jpeg")


@pytest.mark.parametrize("junk", [b"II*\0", b"II*\0\x08\0\0\0\xff\xff", b"not a tiff at all"])
def test_a_malformed_tiff_is_an_error(junk: bytes) -> None:
    with pytest.raises(C2paError) as failure:
        c2pa.read_asset(junk, "tiff")
    assert failure.value.code is ErrorCode.READ


def test_every_host_produces_the_same_signed_tiff(tmp_path: Path) -> None:
    source = tiff("<", True)
    memory = sign(source)

    sink = io.BytesIO()
    with BuildSession(baseline_definition(), "tiff", "es256", [CERTIFICATE]) as session:
        c2pa.drive_build(session, StreamBuildHost(io.BytesIO(source), sink, signer=signer))

    (tmp_path / "in.tif").write_bytes(source)
    with BuildSession(baseline_definition(), "tiff", "es256", [CERTIFICATE]) as session:
        with FileBuildHost(tmp_path / "in.tif", tmp_path / "out.tif", signer=signer) as host:
            c2pa.drive_build(session, host)
            host.publish()

    assert memory == sink.getvalue() == (tmp_path / "out.tif").read_bytes()


def test_file_helpers_choose_the_format_from_the_extension(tmp_path: Path) -> None:
    (tmp_path / "in.tiff").write_bytes(tiff(">", False))
    c2pa.sign_file(
        tmp_path / "in.tiff",
        tmp_path / "out.tiff",
        definition_json=baseline_definition(),
        certificates=[CERTIFICATE],
        signer=signer,
    )
    reader = c2pa.read_asset(tmp_path / "out.tiff", settings_json=trust_settings(), clock=lambda: NOW)
    assert reader is not None and reader.validation_state() is ValidationState.TRUSTED


def test_async_helpers_sign_and_read_a_tiff(tmp_path: Path) -> None:
    (tmp_path / "in.tif").write_bytes(tiff("<", False))

    async def go() -> ValidationState:
        await c2pa.async_sign_file(
            tmp_path / "in.tif",
            tmp_path / "out.tif",
            definition_json=baseline_definition(),
            certificates=[CERTIFICATE],
            signer=signer,
        )
        reader = await c2pa.async_read_asset(
            tmp_path / "out.tif", settings_json=trust_settings(), clock=lambda: NOW
        )
        assert reader is not None
        return reader.validation_state()

    assert run(go()) is ValidationState.TRUSTED
