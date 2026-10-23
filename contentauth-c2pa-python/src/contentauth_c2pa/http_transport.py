"""Optional standard-library HTTP transports for OCSP and RFC 3161 timestamps.

The sessions never touch the network; a host answers `OcspRequest` and `TimestampRequest`
with a callback. These are ready-made callbacks, so a caller who wants the network need
not write one. They are opt-in: pass `http_ocsp` as `read_asset(ocsp=...)` and
`http_timestamper` as `sign_file(timestamper=...)`, or the `async_` forms to the asyncio
drivers.

The two differ in how far their URL is trusted. A timestamp authority's URL comes from the
signing party, so `http_timestamper` only restricts it to `http`/`https`. An OCSP
responder's URL is chosen by a certificate *inside the asset being read*, which is
untrusted input, so `http_ocsp` also refuses to contact anything but publicly routable
addresses (no loopback, private, link-local or cloud-metadata destinations), connects to
the very address it vetted so a second DNS answer cannot redirect it, and refuses
redirects for the same reason. Both bound the response size and the time taken.
"""

import asyncio
from http.client import HTTPConnection, HTTPSConnection
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

MAX_RESPONSE = 1024 * 1024
"""Bytes of response accepted; more than any real OCSP response or timestamp token."""

TIMEOUT = 30.0
"""Seconds allowed for each connect and each read."""

_OCSP_REQUEST = "application/ocsp-request"
_TIMESTAMP_QUERY = "application/timestamp-query"
_TIMESTAMP_REPLY = "application/timestamp-reply"


class HttpError(OSError):
    """The remote service answered, but not with a usable response."""


def _tls_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.partition("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _public_addresses(host: str, port: int) -> list[str]:
    """Resolve `host`, requiring *every* answer to be public, so none can be picked later."""
    found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = [str(info[4][0]) for info in found]
    if not addresses or not all(_is_public(address) for address in addresses):
        raise ValueError(f"{host} does not resolve only to public addresses")
    return addresses


def _connect_pinned(addresses: list[str], port: int) -> socket.socket:
    failure: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), TIMEOUT)
        except OSError as error:
            failure = error
    raise failure if failure is not None else OSError("no address to connect to")


def _post(
    url: str,
    body: bytes,
    content_type: str,
    accept: str | None,
    *,
    public_only: bool,
) -> bytes:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"{url!r} is not an http or https URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("a URL carrying credentials is refused")
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    host = parts.hostname
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

    connection: HTTPConnection
    if secure:
        connection = HTTPSConnection(host, port, timeout=TIMEOUT, context=_tls_context())
    else:
        connection = HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        if public_only:
            sock = _connect_pinned(_public_addresses(host, port), port)
            if secure:
                sock = _tls_context().wrap_socket(sock, server_hostname=host)
            connection.sock = sock
        headers = {"Content-Type": content_type}
        if accept is not None:
            headers["Accept"] = accept
        connection.request("POST", target, body, headers)
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise HttpError(f"{url} answered {response.status} {response.reason}")
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise HttpError(f"the response from {url} exceeds {MAX_RESPONSE} bytes")
        return data
    finally:
        connection.close()


def http_ocsp(url: str, request: bytes) -> bytes:
    """POST a DER OCSP request (RFC 6960 §A.1) to a responder and return the response body.

    The URL is untrusted, so only public destinations are contacted. Any failure raises,
    and the engine treats a responder it could not reach as fail-open.
    """
    return _post(url, request, _OCSP_REQUEST, None, public_only=True)


def http_timestamper(url: str, request: bytes) -> bytes:
    """POST a DER `TimeStampReq` (RFC 3161 §3.4) and return the complete `TimeStampResp`."""
    return _post(url, request, _TIMESTAMP_QUERY, _TIMESTAMP_REPLY, public_only=False)


async def async_http_ocsp(url: str, request: bytes) -> bytes:
    """`http_ocsp` on a worker thread, so the event loop is never blocked.

    A call already in flight when the awaiting task is cancelled still runs until it
    finishes or `TIMEOUT` passes; nothing is delivered to the session afterwards.
    """
    return await asyncio.to_thread(http_ocsp, url, request)


async def async_http_timestamper(url: str, request: bytes) -> bytes:
    """`http_timestamper` on a worker thread, with the same cancellation behavior."""
    return await asyncio.to_thread(http_timestamper, url, request)
