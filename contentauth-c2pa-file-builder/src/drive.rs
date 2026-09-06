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
//! `Read + Seek` source and a plain `Read + Write + Seek` output.
//!
//! This is one possible host, not the only one: [`FileBuilderSession`]
//! itself performs no I/O and never signs anything itself, so a host with
//! asynchronous or network-backed access, or that needs to answer
//! [`FileBuilderRequest::Timestamp`] as well, drives it directly instead
//! of going through this module. The output bound is `Read + Write + Seek`
//! rather than `Write` alone because this session reads back whatever it
//! has already written — to hash the asset for the hard binding, and
//! again once the final manifest replaces the placeholder.

use std::io::{self, Read, Seek, SeekFrom, Write};

use contentauth_c2pa_builder::BuilderSettings;
use contentauth_c2pa_format::FormatHandler;
use contentauth_c2pa_primitives::{ByteRange, HostError, SigningAlg, StreamId};
use contentauth_state_machine::{Session, Step};

use crate::{
    error::Error,
    session::{FileBuilderReply, FileBuilderReport, FileBuilderRequest, FileBuilderSession},
};

/// Builds and signs a manifest for `source`, per `settings`, writing the
/// result to `output` and calling `sign` for every claim signature the
/// build needs.
pub(crate) fn build<H, S, O>(
    handler: H,
    mut source: S,
    mut output: O,
    settings: BuilderSettings,
    mut sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
) -> Result<FileBuilderReport, Error>
where
    H: FormatHandler + Send,
    S: Read + Seek,
    O: Read + Write + Seek,
{
    let source_stream = FileBuilderSession::<H>::SOURCE_STREAM;
    let output_stream = FileBuilderSession::<H>::OUTPUT_STREAM;

    let mut session = FileBuilderSession::new(handler, settings);

    loop {
        if session.advance()? == Step::Complete {
            return session.finish();
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = answer(
                source_stream,
                output_stream,
                &mut source,
                &mut output,
                &mut sign,
                &request.kind,
            );
            session.fulfill(request.id, reply)?;
        }
    }
}

fn answer<S: Read + Seek, O: Read + Write + Seek>(
    source_stream: StreamId,
    output_stream: StreamId,
    source: &mut S,
    output: &mut O,
    sign: &mut impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
    request: &FileBuilderRequest,
) -> FileBuilderReply {
    match request {
        FileBuilderRequest::Read { stream, range } => {
            let read = if *stream == source_stream {
                read_range(source, *range)
            } else if *stream == output_stream {
                read_range(output, *range)
            } else {
                return FileBuilderReply::Failed(HostError::new("unknown stream"));
            };
            match read {
                Ok(bytes) => FileBuilderReply::Bytes(bytes),
                Err(err) => FileBuilderReply::Failed(read_failed(*range, &err)),
            }
        }

        FileBuilderRequest::Length { stream } => {
            let len = if *stream == source_stream {
                stream_len(source)
            } else if *stream == output_stream {
                stream_len(output)
            } else {
                return FileBuilderReply::Failed(HostError::new("unknown stream"));
            };
            match len {
                Ok(len) => FileBuilderReply::Length(len),
                Err(err) => FileBuilderReply::Failed(length_failed(&err)),
            }
        }

        FileBuilderRequest::Write { offset, bytes, .. } => {
            match write_range(output, *offset, bytes) {
                Ok(()) => FileBuilderReply::Written,
                Err(err) => FileBuilderReply::Failed(write_failed(*offset, &err)),
            }
        }

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
/// but is not yet stable; nothing here depends on the position a stream
/// was left at, since every read or write seeks to an absolute offset
/// first.
fn stream_len<R: Seek>(stream: &mut R) -> io::Result<u64> {
    stream.seek(SeekFrom::End(0))
}

/// Seeks to `range.start` and reads exactly `range.len` bytes.
fn read_range<R: Read + Seek>(stream: &mut R, range: ByteRange) -> io::Result<Vec<u8>> {
    let len = usize::try_from(range.len)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    stream.seek(SeekFrom::Start(range.start))?;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Seeks to `offset` and writes `bytes` there.
fn write_range<W: Write + Seek>(stream: &mut W, offset: u64, bytes: &[u8]) -> io::Result<()> {
    stream.seek(SeekFrom::Start(offset))?;
    stream.write_all(bytes)
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

fn write_failed(offset: u64, err: &io::Error) -> HostError {
    HostError::new(format!("could not write at offset {offset}: {err}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::io::Cursor;

    use contentauth_c2pa_format_jpeg::JpegFormat;

    use super::*;

    struct AlwaysFails;

    impl Read for AlwaysFails {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("always fails"))
        }
    }

    impl Write for AlwaysFails {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("always fails"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("always fails"))
        }
    }

    impl Seek for AlwaysFails {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Err(io::Error::other("always fails"))
        }
    }

    /// Seeks successfully but fails every read or write — unlike
    /// [`AlwaysFails`], whose failing `seek` means `read_range`/
    /// `write_range` never reach their own `read`/`write` calls at all.
    struct FailsAfterSeek;

    impl Read for FailsAfterSeek {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read fails"))
        }
    }

    impl Write for FailsAfterSeek {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write fails"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Seek for FailsAfterSeek {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }

    fn source_stream() -> StreamId {
        FileBuilderSession::<JpegFormat>::SOURCE_STREAM
    }

    fn output_stream() -> StreamId {
        FileBuilderSession::<JpegFormat>::OUTPUT_STREAM
    }

    fn never_signs(_alg: SigningAlg, _data: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("should not be asked to sign in this test"))
    }

    /// Every other test passes [`never_signs`] as a signer that must not be
    /// called at all; this one proves what it actually does when it is.
    #[test]
    fn never_signs_reports_a_failure() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut output = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Sign {
                alg: SigningAlg::Es256,
                data: vec![1, 2, 3],
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_read_past_the_end_of_the_source_is_reported_as_failed() {
        let mut source = Cursor::new(vec![1u8, 2, 3]);
        let mut output = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: source_stream(),
                range: ByteRange { start: 0, len: 10 },
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_read_past_the_end_of_the_output_is_reported_as_failed() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut output = Cursor::new(vec![1u8, 2, 3]);
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: output_stream(),
                range: ByteRange { start: 0, len: 10 },
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_seek_failure_answering_length_is_reported_as_failed() {
        let mut output = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut AlwaysFails,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Length {
                stream: source_stream(),
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_seek_failure_answering_read_is_reported_as_failed() {
        let mut output = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut AlwaysFails,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: source_stream(),
                range: ByteRange { start: 0, len: 1 },
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_write_failure_is_reported_as_failed() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut AlwaysFails,
            &mut never_signs,
            &FileBuilderRequest::Write {
                stream: output_stream(),
                offset: 0,
                bytes: vec![1, 2, 3],
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    #[test]
    fn a_successful_write_is_acknowledged_and_readable_back() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut output = Cursor::new(vec![0u8; 4]);

        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Write {
                stream: output_stream(),
                offset: 1,
                bytes: vec![9, 9],
            },
        );
        assert!(matches!(reply, FileBuilderReply::Written));
        assert_eq!(output.into_inner(), [0, 9, 9, 0]);
    }

    /// A read failure past a successful seek — as opposed to
    /// `a_seek_failure_answering_read_is_reported_as_failed`, which never
    /// reaches the actual read at all.
    #[test]
    fn a_read_failure_after_a_successful_seek_is_reported_as_failed() {
        let mut output = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut FailsAfterSeek,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: source_stream(),
                range: ByteRange { start: 0, len: 1 },
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    /// The mirror of the above for a write failure.
    #[test]
    fn a_write_failure_after_a_successful_seek_is_reported_as_failed() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut FailsAfterSeek,
            &mut never_signs,
            &FileBuilderRequest::Write {
                stream: output_stream(),
                offset: 0,
                bytes: vec![1],
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }

    /// A request naming neither stream this host knows about is reported
    /// as failed rather than silently answered from the wrong side.
    #[test]
    fn a_request_for_an_unknown_stream_is_reported_as_failed() {
        let mut source = Cursor::new(vec![1u8, 2, 3]);
        let mut output = Cursor::new(vec![1u8, 2, 3]);
        let unknown = StreamId::new(99);

        let read = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Read {
                stream: unknown,
                range: ByteRange { start: 0, len: 1 },
            },
        );
        assert!(matches!(read, FileBuilderReply::Failed(_)), "{read:?}");

        let length = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Length { stream: unknown },
        );
        assert!(matches!(length, FileBuilderReply::Failed(_)), "{length:?}");
    }

    #[test]
    fn a_failing_signer_is_reported_as_failed() {
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut output = Cursor::new(Vec::<u8>::new());
        let mut sign = |_alg: SigningAlg, _data: &[u8]| -> Result<Vec<u8>, HostError> {
            Err(HostError::new("no key available"))
        };

        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
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
        let mut output = Cursor::new(Vec::<u8>::new());
        let mut sign =
            |_alg: SigningAlg, data: &[u8]| -> Result<Vec<u8>, HostError> { Ok(data.to_vec()) };

        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
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
        let mut output = Cursor::new(Vec::<u8>::new());

        let reply = answer(
            source_stream(),
            output_stream(),
            &mut source,
            &mut output,
            &mut never_signs,
            &FileBuilderRequest::Timestamp {
                digest: vec![1, 2, 3],
                hash_alg: contentauth_c2pa_primitives::HashAlgorithm::Sha256,
            },
        );

        assert!(matches!(reply, FileBuilderReply::Failed(_)), "{reply:?}");
    }
}
