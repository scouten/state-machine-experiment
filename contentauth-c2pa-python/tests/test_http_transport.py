from collections.abc import Callable, Iterator
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
import socket
import ssl
import threading
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

import contentauth_c2pa as c2pa
from contentauth_c2pa import HttpError, http_transport
from async_support import run

PUBLIC = "93.184.216.34"


class Recorded:
    def __init__(self, method: str, path: str, headers: dict[str, str], body: bytes) -> None:
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body


class Responder:
    """A loopback HTTP(S) server answering by path, recording what it was sent."""

    def __init__(self, tls: ssl.SSLContext | None = None) -> None:
        recorded: list[Recorded] = []
        self.requests = recorded
        self.big = 0

        responder = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                recorded.append(
                    Recorded("POST", self.path, dict(self.headers), self.rfile.read(length))
                )
                route = self.path.split("?")[0]
                if route == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if route == "/fail":
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                payload = b"x" * responder.big if route == "/big" else b"reply"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls is not None:
            self._server.socket = tls.wrap_socket(self._server.socket, server_side=True)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self._thread.start()

    def url(self, path: str = "/", scheme: str = "http", host: str = "127.0.0.1") -> str:
        return f"{scheme}://{host}:{self.port}{path}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()


@pytest.fixture
def responder() -> Iterator[Responder]:
    server = Responder()
    yield server
    server.close()


def _certificate(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def tls_responder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Responder]:
    cert, key = _certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(http_transport, "_tls_context", lambda: client_context)
    server = Responder(server_context)
    yield server
    server.close()


def _resolve_to(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    real = socket.getaddrinfo

    def getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        if host == "127.0.0.1":  # the test's own connection to its loopback server
            return real(host, port, *args, **kwargs)  # type: ignore[no-any-return]
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
            for a in addresses
        ]

    monkeypatch.setattr(http_transport.socket, "getaddrinfo", getaddrinfo)


def _connect_to(
    monkeypatch: pytest.MonkeyPatch, server: Responder
) -> list[tuple[str, int]]:
    """Send every connection to `server`, recording the address it was really aimed at."""
    aimed: list[tuple[str, int]] = []
    real = socket.create_connection

    def create_connection(address: tuple[str, int], timeout: float) -> socket.socket:
        aimed.append(address)
        return real(("127.0.0.1", server.port), timeout)

    monkeypatch.setattr(http_transport.socket, "create_connection", create_connection)
    return aimed


# ---- timestamps -----------------------------------------------------------------


def test_timestamper_posts_the_request_and_returns_the_response(responder: Responder) -> None:
    assert c2pa.http_timestamper(responder.url("/tsa?profile=1"), b"query") == b"reply"
    (sent,) = responder.requests
    assert (sent.method, sent.path, sent.body) == ("POST", "/tsa?profile=1", b"query")
    assert sent.headers["Content-Type"] == "application/timestamp-query"
    assert sent.headers["Accept"] == "application/timestamp-reply"


def test_timestamper_defaults_the_path_to_the_root(responder: Responder) -> None:
    c2pa.http_timestamper(responder.url(""), b"q")
    assert responder.requests[0].path == "/"


def test_timestamper_reaches_a_loopback_authority_it_trusts(responder: Responder) -> None:
    # The URL comes from the signing party, so unlike OCSP it is not restricted to public hosts.
    assert c2pa.http_timestamper(responder.url(host="localhost"), b"q") == b"reply"


def test_timestamper_reports_an_error_status(responder: Responder) -> None:
    with pytest.raises(HttpError, match="500"):
        c2pa.http_timestamper(responder.url("/fail"), b"q")


def test_redirects_are_refused(responder: Responder) -> None:
    with pytest.raises(HttpError, match="302"):
        c2pa.http_timestamper(responder.url("/redirect"), b"q")
    assert [r.path for r in responder.requests] == ["/redirect"]


def test_the_response_size_is_bounded(
    responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http_transport, "MAX_RESPONSE", 16)
    responder.big = 16
    assert c2pa.http_timestamper(responder.url("/big"), b"q") == b"x" * 16
    responder.big = 17
    with pytest.raises(HttpError, match="exceeds 16 bytes"):
        c2pa.http_timestamper(responder.url("/big"), b"q")


def test_an_unreachable_server_raises_the_network_error() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    with pytest.raises(OSError):
        c2pa.http_timestamper(f"http://127.0.0.1:{port}/", b"q")


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/tsa",
        "file:///etc/passwd",
        "example.com/tsa",
        "http:///tsa",
        "http://user:secret@example.com/tsa",
        "http://user@example.com/tsa",
    ],
)
@pytest.mark.parametrize("transport", [c2pa.http_timestamper, c2pa.http_ocsp])
def test_only_plain_http_and_https_urls_are_accepted(
    transport: Callable[[str, bytes], bytes], url: str
) -> None:
    with pytest.raises(ValueError):
        transport(url, b"q")


# ---- OCSP -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_ocsp_refuses_non_public_destinations_without_connecting(
    responder: Responder, monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    _resolve_to(monkeypatch, address)
    aimed = _connect_to(monkeypatch, responder)
    with pytest.raises(ValueError, match="public addresses"):
        c2pa.http_ocsp("http://responder.example/ocsp", b"q")
    assert aimed == [] and responder.requests == []


def test_ocsp_refuses_a_literal_loopback_address(responder: Responder) -> None:
    with pytest.raises(ValueError, match="public addresses"):
        c2pa.http_ocsp(responder.url("/ocsp"), b"q")
    assert responder.requests == []


def test_ocsp_refuses_a_name_with_any_non_public_answer(
    responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resolve_to(monkeypatch, PUBLIC, "10.0.0.1")
    aimed = _connect_to(monkeypatch, responder)
    with pytest.raises(ValueError, match="public addresses"):
        c2pa.http_ocsp("http://responder.example/ocsp", b"q")
    assert aimed == []


def test_ocsp_refuses_a_name_with_no_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_to(monkeypatch)
    with pytest.raises(ValueError, match="public addresses"):
        c2pa.http_ocsp("http://responder.example/ocsp", b"q")


def test_ocsp_connects_to_the_address_it_vetted(
    responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resolve_to(monkeypatch, PUBLIC)
    aimed = _connect_to(monkeypatch, responder)
    assert c2pa.http_ocsp("http://ocsp.example/status", b"der") == b"reply"
    assert aimed == [(PUBLIC, 80)]
    (sent,) = responder.requests
    assert (sent.path, sent.body) == ("/status", b"der")
    assert sent.headers["Content-Type"] == "application/ocsp-request"
    assert sent.headers["Host"] == "ocsp.example"
    assert "Accept" not in sent.headers


def test_ocsp_does_not_follow_a_redirect(
    responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resolve_to(monkeypatch, PUBLIC)
    _connect_to(monkeypatch, responder)
    with pytest.raises(HttpError, match="302"):
        c2pa.http_ocsp("http://ocsp.example/redirect", b"q")
    assert len(responder.requests) == 1


def test_pinned_connection_tries_each_address_in_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []
    sentinel = object()

    def create_connection(address: tuple[str, int], timeout: float) -> Any:
        attempts.append(address[0])
        if address[0] == "first":
            raise ConnectionRefusedError("first")
        return sentinel

    monkeypatch.setattr(http_transport.socket, "create_connection", create_connection)
    assert http_transport._connect_pinned(["first", "second"], 80) is sentinel
    assert attempts == ["first", "second"]

    with pytest.raises(ConnectionRefusedError, match="first"):
        http_transport._connect_pinned(["first"], 80)
    with pytest.raises(OSError, match="no address"):
        http_transport._connect_pinned([], 80)


# ---- TLS ------------------------------------------------------------------------


def test_https_timestamper_verifies_the_certificate(tls_responder: Responder) -> None:
    url = tls_responder.url("/tsa", scheme="https", host="localhost")
    assert c2pa.http_timestamper(url, b"q") == b"reply"


def test_https_timestamper_rejects_an_untrusted_certificate(
    tls_responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http_transport, "_tls_context", ssl.create_default_context)
    with pytest.raises(ssl.SSLError):
        c2pa.http_timestamper(tls_responder.url(scheme="https", host="localhost"), b"q")


def test_https_ocsp_pins_the_address_and_checks_the_name(
    tls_responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resolve_to(monkeypatch, PUBLIC)
    aimed = _connect_to(monkeypatch, tls_responder)
    # The certificate names `localhost`, which is what the URL says, though the socket goes
    # to the vetted address.
    assert c2pa.http_ocsp(f"https://localhost:{tls_responder.port}/s", b"der") == b"reply"
    assert aimed == [(PUBLIC, tls_responder.port)]

    with pytest.raises(ssl.SSLCertVerificationError):
        c2pa.http_ocsp(f"https://other.example:{tls_responder.port}/s", b"der")


# ---- asyncio --------------------------------------------------------------------


def test_async_timestamper_matches_the_blocking_one(responder: Responder) -> None:
    assert run(c2pa.async_http_timestamper(responder.url("/tsa"), b"q")) == b"reply"


def test_async_ocsp_applies_the_same_destination_rules(responder: Responder) -> None:
    with pytest.raises(ValueError, match="public addresses"):
        run(c2pa.async_http_ocsp(responder.url("/ocsp"), b"q"))
    assert responder.requests == []


def test_async_ocsp_reaches_a_vetted_address(
    responder: Responder, monkeypatch: pytest.MonkeyPatch
) -> None:
    _resolve_to(monkeypatch, PUBLIC)
    _connect_to(monkeypatch, responder)
    assert run(c2pa.async_http_ocsp("http://ocsp.example/s", b"der")) == b"reply"


def test_the_default_tls_context_verifies_certificates_and_names() -> None:
    context = http_transport._tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
