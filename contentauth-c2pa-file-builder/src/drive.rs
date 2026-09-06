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

//! A synchronous [`FileBuilderSession`] host for callers with a plain
//! `Read + Seek` source and a plain signing function.
//!
//! This is one possible host, not the only one: [`FileBuilderSession`]
//! itself performs no I/O and never signs anything itself, so a host with
//! asynchronous or network-backed access to the source, or that needs to
//! answer [`FileBuilderRequest::Timestamp`] as well, drives it directly
//! instead of going through this module.

use std::io::{self, Read, Seek, SeekFrom};

use contentauth_c2pa_builder::BuilderSettings;
use contentauth_c2pa_format::FormatHandler;
use contentauth_c2pa_primitives::{ByteRange, HostError, SigningAlg};
use contentauth_state_machine::{Session, Step};

use crate::{
    error::Error,
    session::{FileBuilderReply, FileBuilderReport, FileBuilderRequest, FileBuilderSession},
};

/// Builds and signs a manifest for `source`, per `settings`, calling
/// `sign` for every claim signature the build needs.
pub(crate) fn build<H: FormatHandler + Send, R: Read + Seek>(
    handler: H,
    mut source: R,
    settings: BuilderSettings,
    mut sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
) -> Result<FileBuilderReport, Error> {
    let mut session = FileBuilderSession::new(handler, settings);

    loop {
        if session.advance()? == Step::Complete {
            return session.finish();
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = answer(&mut source, &mut sign, &request.kind);
            session.fulfill(request.id, reply)?;
        }
    }
}

fn answer<R: Read + Seek>(
    source: &mut R,
    sign: &mut impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
    request: &FileBuilderRequest,
) -> FileBuilderReply {
    match request {
        FileBuilderRequest::Read { range, .. } => match read_range(source, *range) {
            Ok(bytes) => FileBuilderReply::Bytes(bytes),
            Err(err) => FileBuilderReply::Failed(read_failed(*range, &err)),
        },

        FileBuilderRequest::Length { .. } => match stream_len(source) {
            Ok(len) => FileBuilderReply::Length(len),
            Err(err) => FileBuilderReply::Failed(length_failed(&err)),
        },

        FileBuilderRequest::Sign { alg, data } => match sign(*alg, data) {
            Ok(signature) => FileBuilderReply::Signature(signature),
            Err(err) => FileBuilderReply::Failed(err),
        },

        FileBuilderRequest::Timestamp { .. } => FileBuilderReply::Failed(HostError::new(
            "this host does not support RFC 3161 timestamping; \
             drive FileBuilderSession directly to add it",
        )),
    }
}

/// The stream's total length, found by seeking to its end.
///
/// `Seek::stream_len` would do this (and restore the original position),
/// but is not yet stable; nothing here depends on the position `source`
/// was left at, since every read seeks to an absolute offset first.
fn stream_len<R: Seek>(source: &mut R) -> io::Result<u64> {
    source.seek(SeekFrom::End(0))
}

/// Seeks to `range.start` and reads exactly `range.len` bytes.
fn read_range<R: Read + Seek>(source: &mut R, range: ByteRange) -> io::Result<Vec<u8>> {
    let len = usize::try_from(range.len)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    source.seek(SeekFrom::Start(range.start))?;
    let mut buf = vec![0u8; len];
    source.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_failed(range: ByteRange, err: &io::Error) -> HostError {
    HostError::new(format!(
        "could not read {}+{} bytes: {err}",
        range.start, range.len
    ))
}

fn length_failed(err: &io::Error) -> HostError {
    HostError::new(format!("could not determine stream length: {err}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::io::Cursor;

    use contentauth_c2pa_primitives::StreamId;

    use super::*;

    struct AlwaysFails;

    impl Read for AlwaysFails {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("always fails"))
        }
    }

    impl Seek for AlwaysFails {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Err(io::Error::other("always fails"))
        }
    }

    fn stream() -> StreamId {
        StreamId::new(0)
    }

    fn never_signs(_alg: SigningAlg, _data: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("should not be asked to sign in this test"))
    }

    #[test]
    fn a_read_past_the_end_of_the_source_is_reported_as_failed() {
        let mut source = Cursor::new(vec![1u8, 2, 3]);
        let reply = answer(
            &mut source,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: stream(),
                range: ByteRange { start: 0, len: 10 },
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_seek_failure_answering_length_is_reported_as_failed() {
        let reply = answer(
            &mut AlwaysFails,
            &mut never_signs,
            &FileBuilderRequest::Length { stream: stream() },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_seek_failure_answering_read_is_reported_as_failed() {
        let reply = answer(
            &mut AlwaysFails,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: stream(),
                range: ByteRange { start: 0, len: 1 },
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_failing_signer_is_reported_as_failed() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut sign = |_alg: SigningAlg, _data: &[u8]| -> Result<Vec<u8>, HostError> {
            Err(HostError::new("no key available"))
        };

        let reply = answer(
            &mut source,
            &mut sign,
            &FileBuilderRequest::Sign {
                alg: SigningAlg::Es256,
                data: vec![1, 2, 3],
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_successful_signer_answers_with_its_signature() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut sign =
            |_alg: SigningAlg, data: &[u8]| -> Result<Vec<u8>, HostError> { Ok(data.to_vec()) };

        let reply = answer(
            &mut source,
            &mut sign,
            &FileBuilderRequest::Sign {
                alg: SigningAlg::Es256,
                data: vec![1, 2, 3],
            },
        );

        assert!(matches!(reply, FileBuilderReply::Signature(bytes) if bytes == [1, 2, 3]));
    }

    #[test]
    fn timestamp_requests_are_always_reported_as_unsupported() {
        let mut source = Cursor::new(Vec::<u8>::new());

        let reply = answer(
            &mut source,
            &mut never_signs,
            &FileBuilderRequest::Timestamp {
                digest: vec![1, 2, 3],
                hash_alg: contentauth_c2pa_primitives::HashAlgorithm::Sha256,
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }
}
