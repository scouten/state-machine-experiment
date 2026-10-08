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

//! The one-pass property, proved on RIFF: building and signing a WAV
//! reads the source once and writes the output once, and never reads the
//! output back — the hard binding's digest is accumulated as the output is
//! produced.
//!
//! The host here is a recording one: it answers every request from
//! in-memory buffers and keeps a tally of what was asked of each stream.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_file_builder::{
    build_and_sign, BuilderSettings, FileBuilderReply, FileBuilderRequest, FileBuilderSession,
    GeneratorInfo, HostError, SigningAlg,
};
use contentauth_c2pa_file_reader::read_manifest;
use contentauth_c2pa_format_riff::RiffFormat;
use contentauth_c2pa_reader::{ReadSettings, ValidationState};
use contentauth_state_machine::{Session, Step};

const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

fn settings() -> BuilderSettings {
    let mut settings = BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-file-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.title = Some("test.wav".to_string());
    settings
}

fn sign(alg: SigningAlg, data: &[u8]) -> Result<Vec<u8>, HostError> {
    assert_eq!(alg, SigningAlg::Es256);
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .map_err(|err| HostError::new(err.to_string()))?;
    signer
        .sign(data)
        .map_err(|err| HostError::new(err.to_string()))
}

/// A WAV: `fmt ` and `data` chunks, `samples` bytes of audio, and then a
/// trailing `LIST` chunk as many writers leave.
fn wav(samples: usize) -> Vec<u8> {
    let chunk = |id: &[u8; 4], data: &[u8]| {
        let mut out = id.to_vec();
        out.extend((data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
        out
    };

    let mut fmt = vec![1, 0, 1, 0];
    fmt.extend(8000u32.to_le_bytes());
    fmt.extend(8000u32.to_le_bytes());
    fmt.extend([1, 0, 8, 0]);
    let audio: Vec<u8> = (0..samples).map(|i| (i % 251) as u8).collect();

    let mut body = b"WAVE".to_vec();
    body.extend(chunk(b"fmt ", &fmt));
    body.extend(chunk(b"data", &audio));
    body.extend(chunk(b"LIST", b"INFOISFT\x04\0\0\0abc\0"));

    let mut file = b"RIFF".to_vec();
    file.extend((body.len() as u32).to_le_bytes());
    file.extend(body);
    file
}

/// What a build asked of its host.
#[derive(Debug, Default)]
struct Tally {
    source_reads: usize,
    source_bytes_read: u64,
    output_reads: usize,
    output_lengths: usize,
    output_writes: usize,
    output_bytes_written: u64,
    largest_read: u64,
}

/// Drives a build by hand against in-memory streams, recording every
/// request.
fn build(source: &[u8]) -> (Vec<u8>, Tally) {
    let mut session = FileBuilderSession::new(RiffFormat, settings());
    let mut output: Vec<u8> = Vec::new();
    let mut tally = Tally::default();

    let source_stream = FileBuilderSession::<RiffFormat>::SOURCE_STREAM;
    let output_stream = FileBuilderSession::<RiffFormat>::OUTPUT_STREAM;

    loop {
        if session.advance().unwrap() == Step::Complete {
            session.finish().unwrap();
            return (output, tally);
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                FileBuilderRequest::Read { stream, range } => {
                    if *stream == source_stream {
                        tally.source_reads += 1;
                        tally.source_bytes_read += range.len;
                        tally.largest_read = tally.largest_read.max(range.len);
                        let start = range.start as usize;
                        FileBuilderReply::Bytes(source[start..start + range.len as usize].to_vec())
                    } else {
                        assert_eq!(*stream, output_stream);
                        tally.output_reads += 1;
                        FileBuilderReply::Failed(HostError::new("the output is write-only"))
                    }
                }
                FileBuilderRequest::Length { stream } => {
                    if *stream == source_stream {
                        FileBuilderReply::Length(source.len() as u64)
                    } else {
                        tally.output_lengths += 1;
                        FileBuilderReply::Failed(HostError::new("the output is write-only"))
                    }
                }
                FileBuilderRequest::Write { offset, bytes, .. } => {
                    tally.output_writes += 1;
                    tally.output_bytes_written += bytes.len() as u64;
                    let start = *offset as usize;
                    if output.len() < start + bytes.len() {
                        output.resize(start + bytes.len(), 0);
                    }
                    output[start..start + bytes.len()].copy_from_slice(bytes);
                    FileBuilderReply::Written
                }
                FileBuilderRequest::Sign { alg, data, .. } => match sign(*alg, data) {
                    Ok(signature) => FileBuilderReply::Signature(signature),
                    Err(err) => FileBuilderReply::Failed(err),
                },
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

fn read_back(asset: &[u8]) -> contentauth_c2pa_reader::ReadReport {
    read_manifest(
        &RiffFormat,
        std::io::Cursor::new(asset.to_vec()),
        ReadSettings {
            trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
            ..ReadSettings::default()
        },
    )
    .expect("the signed WAV reads back")
}

#[test]
fn a_wav_is_signed_without_the_output_ever_being_read() {
    let source = wav(10_001);
    let (output, tally) = build(&source);

    assert_eq!(tally.output_reads, 0, "{tally:?}");
    assert_eq!(tally.output_lengths, 0, "{tally:?}");

    let report = read_back(&output);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn the_source_is_read_once_and_the_output_written_about_once() {
    let source = wav(5 * 1024 * 1024 + 1);
    let (output, tally) = build(&source);

    assert_eq!(tally.output_reads, 0);

    // Every byte of the output was written once, plus the final manifest
    // rewriting the placeholder's slot: nothing is written twice that need
    // not be.
    let manifest_len = output.len() as u64 - source.len() as u64 - 8 - 12 + 12;
    assert!(
        tally.output_bytes_written <= output.len() as u64 + manifest_len + 1,
        "{tally:?}"
    );

    // The source is read once through, bounded per request (the scan reads
    // a few small windows of headers; the audio moves in 1 MiB pieces),
    // not once to copy and again to hash.
    assert!(
        tally.source_bytes_read < source.len() as u64 + 64 * 1024,
        "{tally:?}"
    );
    assert!(tally.largest_read <= 1 << 20, "{tally:?}");

    let report = read_back(&output);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn the_convenience_host_signs_a_wav_into_a_write_only_view_of_the_output() {
    // `build_and_sign` needs no `Read` on the output: a type that only
    // implements `Write + Seek` will do.
    struct WriteOnly(std::io::Cursor<Vec<u8>>);
    impl std::io::Write for WriteOnly {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
    impl std::io::Seek for WriteOnly {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }

    let source = wav(2_000);
    let mut output = WriteOnly(std::io::Cursor::new(Vec::new()));
    build_and_sign(
        RiffFormat,
        std::io::Cursor::new(source),
        &mut output,
        settings(),
        sign,
        None,
        None,
    )
    .unwrap();

    let report = read_back(&output.0.into_inner());
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn signing_a_signed_wav_replaces_its_manifest() {
    let (once, _) = build(&wav(3_333));
    let (twice, tally) = build(&once);

    assert_eq!(tally.output_reads, 0);
    let report = read_back(&twice);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    // One store, not two.
    assert_eq!(twice.len(), once.len());
}
