// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! [`read_and_validate`]: the host behind [`crate::Reader::with_file`].
//!
//! # Why this crate drives [`FileReadSession`] itself
//!
//! `contentauth-c2pa-file-reader`'s own convenience function,
//! `read_manifest_from_file`, answers every request it can from a local
//! `Read + Seek` source and the wall clock — but it has no network access
//! of its own, and answers [`FileReadRequest::Ocsp`] with
//! [`FileReadReply::Failed`] on principle (see that crate's `drive`
//! module). Getting a *live* OCSP check therefore means driving
//! [`FileReadSession`] directly, exactly as that crate's own docs invite a
//! host with more to offer than a local file and a clock to do.
//!
//! This is deliberately the only place in the whole workspace that names
//! [`reqwest`]: every other crate here is sans-I/O by design (see the root
//! `CLAUDE.md`), and `contentauth-c2pa-reader` already builds and
//! interprets the OCSP request/response bytes on its own — this module's
//! job is nothing more than the one thing a sans-I/O core cannot do for
//! itself, an HTTP POST.
//!
//! # What this host answers, and how
//!
//! * [`FileReadRequest::Read`] / [`FileReadRequest::Length`] — the file
//!   opened for [`crate::Reader::with_file`], seeking to whatever range is
//!   asked for.
//! * [`FileReadRequest::CurrentDateTime`] — the wall clock.
//! * [`FileReadRequest::Ocsp`] — a blocking POST of the given DER bytes to
//!   the given responder URL, with `Content-Type: application/ocsp-request`
//!   per RFC 6960 §4.1, reporting back the response body verbatim. Any
//!   failure — a network error, a non-success HTTP status, an unreachable
//!   responder — answers with [`FileReadReply::Failed`] rather than
//!   propagating: OCSP checking is fail-open (see
//!   [`ReadSettings::check_ocsp`](contentauth_c2pa_reader::ReadSettings::check_ocsp)),
//!   so a manifest is validated exactly as it would be if this host had no
//!   network access at all.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use contentauth_c2pa_file_reader::{
    FileReadReply, FileReadRequest, FileReadSession, FormatHandler, ReadReport, ReadSettings,
};
use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_state_machine::{Session, Step};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::error::Error;

/// The media type RFC 6960 §4.1 names for an OCSP request body.
const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

/// A generous upper bound on a well-formed OCSP response's size.
///
/// RFC 6960 responses are ordinarily a few KB even with an embedded
/// responder certificate attached; this leaves ample headroom while still
/// bounding memory use against a responder URL this host does not
/// control — see [`fetch_ocsp`].
const MAX_OCSP_RESPONSE_BYTES: u64 = 64 * 1024;

/// Opens `path`, then locates and reads its C2PA manifest store, answering
/// every request [`FileReadSession`] issues — network requests included.
pub(crate) fn read_and_validate<H: FormatHandler>(
    handler: &H,
    path: &Path,
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    let mut source = File::open(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let client = reqwest::blocking::Client::builder()
        .dns_resolver(Arc::new(PublicOnlyResolver))
        .build()?;
    let mut session = FileReadSession::new(handler, settings);

    loop {
        if session.advance()? == Step::Complete {
            return Ok(session.finish()?);
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = answer(&mut source, &client, &request.kind);
            session.fulfill(request.id, reply)?;
        }
    }
}

fn answer(
    source: &mut File,
    client: &reqwest::blocking::Client,
    request: &FileReadRequest,
) -> FileReadReply {
    match request {
        FileReadRequest::Read { range, .. } => match read_range(source, *range) {
            Ok(bytes) => FileReadReply::Bytes(bytes),
            Err(err) => FileReadReply::Failed(HostError::new(format!(
                "could not read {}+{} bytes: {err}",
                range.start, range.len
            ))),
        },

        FileReadRequest::Length { .. } => match source.seek(SeekFrom::End(0)) {
            Ok(len) => FileReadReply::Length(len),
            Err(err) => FileReadReply::Failed(HostError::new(format!(
                "could not determine stream length: {err}"
            ))),
        },

        FileReadRequest::CurrentDateTime => FileReadReply::CurrentDateTime(now_unix()),

        FileReadRequest::Ocsp { url, request_der } => fetch_ocsp(client, url, request_der),

        // `FileReadRequest` is `#[non_exhaustive]`; a variant this host
        // does not yet know how to answer is reported as unsupported
        // rather than a compile error the next time it grows one.
        _ => FileReadReply::Failed(HostError::new("unsupported request")),
    }
}

/// Seeks to `range.start` and reads exactly `range.len` bytes.
fn read_range(source: &mut File, range: ByteRange) -> io::Result<Vec<u8>> {
    let len = usize::try_from(range.len)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    source.seek(SeekFrom::Start(range.start))?;
    let mut buf = vec![0u8; len];
    source.read_exact(&mut buf)?;
    Ok(buf)
}

/// The current wall-clock time as Unix seconds, falling back to the epoch
/// for a clock reading before it — a hypothetical this crate has no better
/// answer for, and the reader treats as any other implausible time.
fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// POSTs `request_der` to `url` as an OCSP request, and returns whatever
/// bytes came back.
///
/// `url` is untrusted input — it comes from a certificate embedded in
/// whatever asset is being read — so this refuses anything but `http`/
/// `https`, and the client this is called with (see [`read_and_validate`])
/// refuses to resolve `url`'s host to anything but a public address, so a
/// crafted certificate cannot turn this host into a proxy for loopback,
/// link-local, or other private network destinations. The response body
/// is also capped at [`MAX_OCSP_RESPONSE_BYTES`], so a responder this host
/// does reach cannot exhaust memory with an oversized reply.
///
/// Never returns an error of its own: every failure mode — a disallowed
/// URL, the responder is unreachable, times out, answers with a
/// non-success HTTP status, or answers with too much data — comes back as
/// [`FileReadReply::Failed`], which [`contentauth_c2pa_reader`]'s
/// fail-open OCSP handling treats exactly like "this certificate's
/// revocation status could not be checked."
fn fetch_ocsp(client: &reqwest::blocking::Client, url: &str, request_der: &[u8]) -> FileReadReply {
    match fetch_ocsp_checked(client, url, request_der) {
        Ok(bytes) => FileReadReply::OcspResponse(bytes),
        Err(message) => FileReadReply::Failed(HostError::new(message)),
    }
}

fn fetch_ocsp_checked(
    client: &reqwest::blocking::Client,
    url: &str,
    request_der: &[u8],
) -> Result<Vec<u8>, String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|err| format!("OCSP responder URL {url} could not be parsed: {err}"))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "OCSP responder URL {url} does not use the http or https scheme"
        ));
    }

    // A literal IP host bypasses DNS resolution entirely — `reqwest`
    // never calls `PublicOnlyResolver::resolve` for one — so it has to be
    // checked here directly rather than relying only on that hook, which
    // still covers a hostname that merely *resolves* to a private address.
    let literal_host_is_disallowed = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => !is_global(&IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => !is_global(&IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) | None => false,
    };
    if literal_host_is_disallowed {
        return Err(format!(
            "OCSP responder URL {url} does not name a public address"
        ));
    }

    send_ocsp_request(client, parsed, request_der)
        .map_err(|err| format!("OCSP request to {url} failed: {err}"))
}

/// The bare HTTP mechanics of [`fetch_ocsp_checked`], with none of its
/// destination checks: POSTs `request_der` to `url` and returns the
/// response body, capped at [`MAX_OCSP_RESPONSE_BYTES`].
///
/// Split out so this crate's own tests can exercise it directly against a
/// local loopback listener — which [`fetch_ocsp_checked`]'s own
/// destination restrictions would otherwise always refuse to contact,
/// same as they would a real attacker-chosen loopback address.
fn send_ocsp_request(
    client: &reqwest::blocking::Client,
    url: reqwest::Url,
    request_der: &[u8],
) -> Result<Vec<u8>, String> {
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
        .body(request_der.to_vec())
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| err.to_string())?;

    // `take` bounds how much is ever buffered in memory, regardless of
    // what the responder claims or omits in `Content-Length`; reading one
    // byte past the limit is how the check below tells "exactly at the
    // limit" from "over it" without a second round trip.
    let mut bytes = Vec::new();
    response
        .take(MAX_OCSP_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;

    if bytes.len() as u64 > MAX_OCSP_RESPONSE_BYTES {
        return Err(format!(
            "response exceeded the {MAX_OCSP_RESPONSE_BYTES}-byte limit"
        ));
    }

    Ok(bytes)
}

/// A DNS resolver that refuses to resolve a hostname to anything but a
/// public, globally-routable address.
///
/// The OCSP responder URL [`fetch_ocsp`] posts to comes from a
/// certificate embedded in whatever asset is being read — untrusted input
/// from whoever crafted that certificate. Without this, a certificate
/// naming, say, `http://169.254.169.254/` (a common cloud metadata
/// endpoint) or a hostname that merely *resolves* to a loopback or private
/// address would make this host issue an HTTP request to a destination
/// the asset itself chose, entirely outside what `Reader::with_file` is
/// meant to reach. Hooking this in at DNS resolution rather than checking
/// the literal URL closes both cases, and covers a redirect to a
/// different host the same way, since every connection `reqwest` makes is
/// resolved through this hook.
///
/// This is a best-effort mitigation, not a complete one: an attacker who
/// controls DNS for the responder's hostname could still race a public
/// answer at resolution time against a private one at connect time
/// (classic DNS rebinding). Closing that fully would mean binding the
/// exact address this resolver returned rather than letting a later stage
/// of the connection re-resolve it, which is a larger undertaking than
/// this experimental compatibility layer's scope justifies today.
#[derive(Debug, Default)]
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            // A blocking lookup, same as the default resolver's own
            // `getaddrinfo` call — safe here because `reqwest::blocking`
            // already dedicates a single background thread to driving one
            // request at a time for this client.
            let addrs = (name.as_str(), 0)
                .to_socket_addrs()
                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { Box::new(err) })?;

            let allowed: Vec<SocketAddr> = addrs.filter(|addr| is_global(&addr.ip())).collect();

            if allowed.is_empty() {
                return Err(
                    format!("{} does not resolve to a public address", name.as_str()).into(),
                );
            }

            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// True for an [`IpAddr`] that is publicly routable — not loopback,
/// private, link-local, unspecified, multicast, or one of the other
/// special-use ranges a responder embedded in untrusted input should not
/// be able to direct this host toward.
fn is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        // An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is judged by the
        // v4 address it embeds, not by IPv6's (much shorter) special-use
        // list, since that is the address a dual-stack connection would
        // actually reach.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_global_v4(&v4),
            None => is_global_v6(v6),
        },
    }
}

fn is_global_v4(ip: &Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || is_carrier_grade_nat_v4(ip))
}

/// `100.64.0.0/10` (RFC 6598): carrier-grade NAT space, also used by some
/// cloud providers for internal addressing — not covered by any stable
/// `Ipv4Addr` predicate.
fn is_carrier_grade_nat_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0b1100_0000) == 0b0100_0000
}

fn is_global_v6(ip: &Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_unique_local_v6(ip)
        || is_unicast_link_local_v6(ip))
}

/// `fc00::/7` (RFC 4193): IPv6 unique local addresses, IPv6's rough
/// equivalent of IPv4 private space — not covered by any stable
/// `Ipv6Addr` predicate.
fn is_unique_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// `fe80::/10`: IPv6 link-local addresses.
fn is_unicast_link_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    use super::*;

    /// Starts a one-shot HTTP/1.1 server on an ephemeral local port that
    /// replies once with `response_body`, and returns its base URL
    /// alongside a channel that yields the bytes it actually received.
    ///
    /// This is deliberately not a real HTTP server: it reads whatever
    /// arrives in a single `read` call and treats that as the whole
    /// request, which is safe for a same-host loopback connection carrying
    /// a payload well under one TCP segment — exactly what this module's
    /// own tests send. Real OCSP protocol behavior (CertID matching,
    /// signature verification, freshness) is `contentauth-c2pa-reader`'s
    /// own `ocsp` module's job; this exists only to prove `fetch_ocsp`
    /// makes the HTTP request it claims to, and reports back what a
    /// responder said.
    fn spawn_responder(response_body: Vec<u8>) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds an ephemeral port");
        let addr = listener.local_addr().expect("has a local address");
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts one connection");

            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("reads the request");
            tx.send(buf[..n].to_vec())
                .expect("the receiver is still around");

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                response_body.len()
            );
            write_all(&mut stream, response.as_bytes());
            write_all(&mut stream, &response_body);
        });

        (format!("http://{addr}/"), rx)
    }

    fn write_all(stream: &mut TcpStream, bytes: &[u8]) {
        stream.write_all(bytes).expect("writes to the socket");
    }

    /// Parses a test-server URL, for [`send_ocsp_request`] — which takes
    /// an already-parsed `reqwest::Url`, unlike [`fetch_ocsp`].
    fn parse(url: &str) -> reqwest::Url {
        reqwest::Url::parse(url).expect("test URLs are well-formed")
    }

    #[test]
    fn fetch_ocsp_posts_the_request_bytes_with_the_right_content_type() {
        let (url, received) = spawn_responder(vec![0xde, 0xad, 0xbe, 0xef]);
        let client = reqwest::blocking::Client::new();

        let result = send_ocsp_request(&client, parse(&url), &[1, 2, 3]);

        let request = received
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the server received a request");
        let request = String::from_utf8_lossy(&request);

        assert!(request.starts_with("POST "), "{request}");
        assert!(
            request
                .to_lowercase()
                .contains("content-type: application/ocsp-request"),
            "{request}"
        );
        assert!(
            request.as_bytes().windows(3).any(|w| w == [1, 2, 3]),
            "the request body should carry the bytes given to fetch_ocsp: {request:?}"
        );

        assert_eq!(result, Ok(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn fetch_ocsp_reports_an_unreachable_responder_as_failed() {
        // Nothing is listening on this port; the connection itself should
        // fail rather than this function ever getting as far as parsing a
        // response.
        let client = reqwest::blocking::Client::new();
        let result = send_ocsp_request(&client, parse("http://127.0.0.1:1/"), &[1, 2, 3]);

        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn fetch_ocsp_reports_a_non_success_status_as_failed() {
        let (url, _received) = spawn_no_op_error_responder();
        let client = reqwest::blocking::Client::new();

        let result = send_ocsp_request(&client, parse(&url), &[1, 2, 3]);

        assert!(result.is_err(), "{result:?}");
    }

    /// As [`spawn_responder`], but always answers `500 Internal Server
    /// Error` with an empty body — the shape a responder that rejected the
    /// request outright would take at the HTTP layer.
    fn spawn_no_op_error_responder() -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds an ephemeral port");
        let addr = listener.local_addr().expect("has a local address");
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts one connection");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("reads the request");
            tx.send(buf[..n].to_vec())
                .expect("the receiver is still around");

            write_all(
                &mut stream,
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            );
        });

        (format!("http://{addr}/"), rx)
    }

    #[test]
    fn fetch_ocsp_rejects_a_non_http_scheme_without_making_a_request() {
        let client = reqwest::blocking::Client::new();
        let reply = fetch_ocsp(&client, "ftp://example.com/", &[1, 2, 3]);
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn fetch_ocsp_rejects_an_unparseable_url() {
        let client = reqwest::blocking::Client::new();
        let reply = fetch_ocsp(&client, "not a url", &[1, 2, 3]);
        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn fetch_ocsp_accepts_a_response_exactly_at_the_size_limit() {
        let exact = vec![0x42u8; MAX_OCSP_RESPONSE_BYTES as usize];
        let (url, _received) = spawn_responder(exact.clone());
        let client = reqwest::blocking::Client::new();

        let result = send_ocsp_request(&client, parse(&url), &[1, 2, 3]);

        assert_eq!(result, Ok(exact));
    }

    #[test]
    fn fetch_ocsp_rejects_a_response_over_the_size_limit() {
        let oversized = vec![0x42u8; (MAX_OCSP_RESPONSE_BYTES + 1) as usize];
        let (url, _received) = spawn_responder(oversized);
        let client = reqwest::blocking::Client::new();

        let result = send_ocsp_request(&client, parse(&url), &[1, 2, 3]);

        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn a_client_using_the_public_only_resolver_refuses_a_loopback_responder() {
        // `spawn_responder` binds to loopback, so a client whose resolver
        // rejects non-public addresses must never even connect to it.
        let (url, _received) = spawn_responder(vec![0xaa]);
        let client = reqwest::blocking::Client::builder()
            .dns_resolver(Arc::new(PublicOnlyResolver))
            .build()
            .expect("builds");

        let reply = fetch_ocsp(&client, &url, &[1, 2, 3]);

        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn is_global_accepts_ordinary_public_addresses() {
        assert!(is_global(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_global(&"2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn is_global_rejects_ipv4_special_use_ranges() {
        for ip in [
            Ipv4Addr::new(127, 0, 0, 1),       // loopback
            Ipv4Addr::new(10, 0, 0, 1),        // private
            Ipv4Addr::new(172, 16, 0, 1),      // private
            Ipv4Addr::new(192, 168, 1, 1),     // private
            Ipv4Addr::new(169, 254, 169, 254), // link-local (cloud metadata)
            Ipv4Addr::new(0, 0, 0, 0),         // unspecified
            Ipv4Addr::new(255, 255, 255, 255), // broadcast
            Ipv4Addr::new(224, 0, 0, 1),       // multicast
            Ipv4Addr::new(100, 64, 0, 1),      // carrier-grade NAT
        ] {
            assert!(!is_global(&IpAddr::V4(ip)), "{ip} should not be global");
        }

        // Just outside the carrier-grade NAT block on either side.
        assert!(is_global(&IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
        assert!(is_global(&IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0))));
    }

    #[test]
    fn is_global_rejects_ipv6_special_use_ranges() {
        for ip in [
            "::1",                    // loopback
            "::",                     // unspecified
            "ff02::1",                // multicast
            "fc00::1",                // unique local
            "fe80::1",                // link-local
            "::ffff:127.0.0.1",       // IPv4-mapped loopback
            "::ffff:169.254.169.254", // IPv4-mapped link-local
        ] {
            let addr: Ipv6Addr = ip.parse().expect("parses");
            assert!(!is_global(&IpAddr::V6(addr)), "{ip} should not be global");
        }
    }
}
