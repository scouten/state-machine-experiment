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
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use contentauth_c2pa_file_reader::{
    FileReadReply, FileReadRequest, FileReadSession, FormatHandler, ReadReport, ReadSettings,
};
use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_state_machine::{Session, Step};

use crate::error::Error;

/// The media type RFC 6960 §4.1 names for an OCSP request body.
const OCSP_REQUEST_CONTENT_TYPE: &str = "application/ocsp-request";

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

    let client = reqwest::blocking::Client::new();
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
/// Never returns an error of its own: every failure mode — the responder
/// is unreachable, times out, or answers with a non-success HTTP status —
/// comes back as [`FileReadReply::Failed`], which
/// [`contentauth_c2pa_reader`]'s fail-open OCSP handling treats exactly
/// like "this certificate's revocation status could not be checked."
fn fetch_ocsp(client: &reqwest::blocking::Client, url: &str, request_der: &[u8]) -> FileReadReply {
    let outcome = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, OCSP_REQUEST_CONTENT_TYPE)
        .body(request_der.to_vec())
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(|response| response.bytes());

    match outcome {
        Ok(bytes) => FileReadReply::OcspResponse(bytes.to_vec()),
        Err(err) => FileReadReply::Failed(HostError::new(format!(
            "OCSP request to {url} failed: {err}"
        ))),
    }
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

    #[test]
    fn fetch_ocsp_posts_the_request_bytes_with_the_right_content_type() {
        let (url, received) = spawn_responder(vec![0xde, 0xad, 0xbe, 0xef]);
        let client = reqwest::blocking::Client::new();

        let reply = fetch_ocsp(&client, &url, &[1, 2, 3]);

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

        assert!(matches!(
            reply,
            FileReadReply::OcspResponse(bytes) if bytes == [0xde, 0xad, 0xbe, 0xef]
        ));
    }

    #[test]
    fn fetch_ocsp_reports_an_unreachable_responder_as_failed() {
        // Nothing is listening on this port; the connection itself should
        // fail rather than this function ever getting as far as parsing a
        // response.
        let client = reqwest::blocking::Client::new();
        let reply = fetch_ocsp(&client, "http://127.0.0.1:1/", &[1, 2, 3]);

        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn fetch_ocsp_reports_a_non_success_status_as_failed() {
        let (url, _received) = spawn_no_op_error_responder();
        let client = reqwest::blocking::Client::new();

        let reply = fetch_ocsp(&client, &url, &[1, 2, 3]);

        assert!(matches!(reply, FileReadReply::Failed(_)), "{reply:?}");
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
}
