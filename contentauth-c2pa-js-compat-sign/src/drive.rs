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
//! The asynchronous host for [`FileBuilderSession`]: the only place in
//! this crate anything is awaited. Compare
//! `contentauth_c2pa_file_builder::build_and_sign`, the blocking host
//! for the same session — line for line the same loop.

use contentauth_c2pa_file_builder::{
    BuilderSettings, FileBuilderReply, FileBuilderRequest, FileBuilderSession, FormatHandler,
};
use contentauth_c2pa_js_compat::Blob;
use contentauth_c2pa_primitives::{
    tsa::{timestamp_request, timestamp_token},
    ByteRange, HashAlgorithm, HostError,
};
use contentauth_state_machine::{Session, Step};

use crate::{builder::SignedAsset, error::Error, signer::AsyncSigner};

pub(crate) async fn build<H, B, S>(
    handler: H,
    source: &B,
    signer: &S,
    settings: BuilderSettings,
    tsa_url: Option<&str>,
) -> Result<SignedAsset, Error>
where
    H: FormatHandler + Send,
    B: Blob + ?Sized,
    S: AsyncSigner + ?Sized,
{
    let source_stream = FileBuilderSession::<H>::SOURCE_STREAM;
    let output_stream = FileBuilderSession::<H>::OUTPUT_STREAM;

    let mut session = FileBuilderSession::new(handler, settings);
    // Always starts empty, so no stale bytes from a reused buffer can ever
    // sit after the asset (see `build_and_sign`'s docs).
    let mut output: Vec<u8> = Vec::new();

    loop {
        if session.advance()? == Step::Complete {
            let report = session.finish()?;
            return Ok(SignedAsset {
                asset: output,
                manifest: report.manifest,
            });
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                FileBuilderRequest::Read { stream, range } if *stream == source_stream => {
                    match source.bytes(*range).await {
                        Ok(bytes) if bytes.len() as u64 == range.len => {
                            FileBuilderReply::Bytes(bytes)
                        }
                        Ok(bytes) => FileBuilderReply::Failed(HostError::new(format!(
                            "asked for {} bytes at {}, but the blob returned {}",
                            range.len,
                            range.start,
                            bytes.len()
                        ))),
                        Err(err) => FileBuilderReply::Failed(err),
                    }
                }

                FileBuilderRequest::Read { stream, range } if *stream == output_stream => {
                    match slice(&output, *range) {
                        Ok(bytes) => FileBuilderReply::Bytes(bytes.to_vec()),
                        Err(err) => FileBuilderReply::Failed(err),
                    }
                }

                FileBuilderRequest::Length { stream } if *stream == source_stream => {
                    FileBuilderReply::Length(source.size())
                }

                FileBuilderRequest::Length { stream } if *stream == output_stream => {
                    FileBuilderReply::Length(output.len() as u64)
                }

                FileBuilderRequest::Write { offset, bytes, .. } => {
                    match write(&mut output, *offset, bytes) {
                        Ok(()) => FileBuilderReply::Written,
                        Err(err) => FileBuilderReply::Failed(err),
                    }
                }

                FileBuilderRequest::Sign { data, .. } => match signer.sign(data).await {
                    Ok(signature) => FileBuilderReply::Signature(signature),
                    Err(err) => FileBuilderReply::Failed(err),
                },

                FileBuilderRequest::Timestamp { digest, hash_alg } => {
                    match timestamp(signer, tsa_url, *hash_alg, digest).await {
                        Ok(token) => FileBuilderReply::Timestamp(token),
                        Err(err) => FileBuilderReply::Failed(err),
                    }
                }

                // `FileBuilderRequest` is non-exhaustive.
                _ => FileBuilderReply::Failed(HostError::new("unsupported request")),
            };
            session.fulfill(request.id, reply)?;
        }
    }
}

/// One RFC 3161 round trip: encode the `TimeStampReq`, await the signer
/// sending it, unwrap the token from the response.
async fn timestamp<S: AsyncSigner + ?Sized>(
    signer: &S,
    tsa_url: Option<&str>,
    hash_alg: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, HostError> {
    let url = tsa_url.ok_or_else(|| HostError::new("no time-stamp authority URL is configured"))?;
    let request = timestamp_request(digest, hash_alg)?;
    let response = signer.send_timestamp_request(url, &request).await?;
    timestamp_token(&response)
}

fn slice(bytes: &[u8], range: ByteRange) -> Result<&[u8], HostError> {
    let end = range
        .start
        .checked_add(range.len)
        .ok_or_else(|| HostError::new("byte range overflows"))?;
    usize::try_from(range.start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(start, end)| bytes.get(start..end))
        .ok_or_else(|| HostError::new("read past the end of the output"))
}

/// Writes `bytes` at `offset`, zero-filling any gap — what seeking past
/// the end of a file and writing does.
fn write(output: &mut Vec<u8>, offset: u64, bytes: &[u8]) -> Result<(), HostError> {
    let start = usize::try_from(offset).map_err(|_| HostError::new("offset too large"))?;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| HostError::new("write overflows"))?;
    if output.len() < end {
        output.resize(end, 0);
    }
    output[start..end].copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn writes_extend_overwrite_and_zero_fill() {
        let mut out = Vec::new();
        write(&mut out, 0, &[1, 2, 3]).ok();
        write(&mut out, 1, &[9]).ok();
        write(&mut out, 5, &[7]).ok();
        assert_eq!(out, [1, 9, 3, 0, 0, 7]);
    }

    #[test]
    fn a_write_that_cannot_be_addressed_is_an_error() {
        assert!(write(&mut Vec::new(), u64::MAX, &[1]).is_err());
    }

    #[test]
    fn reads_past_the_end_or_overflowing_are_errors() {
        let bytes = [1u8, 2, 3];
        assert_eq!(
            slice(&bytes, ByteRange { start: 1, len: 2 }).ok(),
            Some(&bytes[1..])
        );
        assert!(slice(&bytes, ByteRange { start: 2, len: 2 }).is_err());
        assert!(slice(
            &bytes,
            ByteRange {
                start: u64::MAX,
                len: 1
            }
        )
        .is_err());
    }

    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use contentauth_c2pa_format_jpeg::JpegFormat;
    use contentauth_c2pa_sign_baseline::{fixtures::*, Definition, BASELINE_DEFINITION};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    /// Signs with 64 zero bytes: enough to reach the next request.
    struct NeverSigns;

    impl AsyncSigner for NeverSigns {
        fn alg(&self) -> contentauth_c2pa_primitives::SigningAlg {
            contentauth_c2pa_primitives::SigningAlg::Es256
        }

        fn certs(&self) -> Vec<Vec<u8>> {
            vec![TEST_SIGNER_CERT.to_vec()]
        }

        async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HostError> {
            Ok(vec![0; 64])
        }
    }

    fn settings() -> BuilderSettings {
        Definition::from_json(BASELINE_DEFINITION)
            .and_then(|d| {
                d.into_settings(
                    contentauth_c2pa_primitives::SigningAlg::Es256,
                    vec![TEST_SIGNER_CERT.to_vec()],
                )
            })
            .unwrap_or_else(|_| unreachable!("the baseline definition is valid"))
    }

    /// A blob that answers every read one byte short.
    struct Short;

    impl Blob for Short {
        fn size(&self) -> u64 {
            SOURCE_JPEG.len() as u64
        }

        async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
            Ok(vec![0; (range.len as usize).saturating_sub(1)])
        }
    }

    #[test]
    fn a_short_read_from_the_blob_fails_the_build_rather_than_being_hashed() {
        let err = block_on(build(JpegFormat, &Short, &NeverSigns, settings(), None)).unwrap_err();
        assert!(err.to_string().contains("blob returned"), "{err}");
    }

    /// A signer with an authority that answers with a canned response and
    /// records what it was sent.
    struct Timestamping {
        response: Vec<u8>,
        seen: std::cell::RefCell<Vec<(String, Vec<u8>)>>,
    }

    impl AsyncSigner for Timestamping {
        fn alg(&self) -> contentauth_c2pa_primitives::SigningAlg {
            contentauth_c2pa_primitives::SigningAlg::Es256
        }

        fn certs(&self) -> Vec<Vec<u8>> {
            vec![TEST_SIGNER_CERT.to_vec()]
        }

        async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HostError> {
            Ok(vec![0; 64])
        }

        async fn send_timestamp_request(
            &self,
            url: &str,
            request: &[u8],
        ) -> Result<Vec<u8>, HostError> {
            self.seen
                .borrow_mut()
                .push((url.to_string(), request.to_vec()));
            Ok(self.response.clone())
        }
    }

    fn timestamped_settings() -> BuilderSettings {
        let mut settings = settings();
        settings.timestamp = Some(contentauth_c2pa_file_builder::TimestampSettings::new(
            10_000,
        ));
        settings
    }

    #[test]
    fn a_timestamp_request_is_answered_by_the_signer_and_the_token_embedded() {
        // PKIStatusInfo { granted }, then a token whose content is 300 x 0x42.
        let mut body = vec![0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x2c];
        body.extend([0x42; 300]);
        let mut response = vec![0x30, 0x82];
        response.extend((body.len() as u16).to_be_bytes());
        response.extend(body);
        let signer = Timestamping {
            response,
            seen: Default::default(),
        };

        let signed = block_on(build(
            JpegFormat,
            SOURCE_JPEG,
            &signer,
            timestamped_settings(),
            Some("https://tsa.example/"),
        ))
        .unwrap();

        let seen = signer.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "https://tsa.example/");
        assert_eq!(seen[0].1[0], 0x30);
        assert!(signed
            .manifest
            .windows(300)
            .any(|window| window == [0x42; 300]));
    }

    #[test]
    fn a_signer_with_no_way_to_reach_an_authority_fails_the_build() {
        let err = block_on(build(
            JpegFormat,
            SOURCE_JPEG,
            &NeverSigns,
            timestamped_settings(),
            Some("https://tsa.example/"),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("send_timestamp_request"), "{err}");
    }

    #[test]
    fn a_refusing_authority_fails_the_build() {
        let signer = Timestamping {
            response: vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02],
            seen: Default::default(),
        };
        let err = block_on(build(
            JpegFormat,
            SOURCE_JPEG,
            &signer,
            timestamped_settings(),
            Some("https://tsa.example/"),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
    }

    #[test]
    fn a_timestamp_with_no_url_configured_fails_the_build() {
        let err = block_on(build(
            JpegFormat,
            SOURCE_JPEG,
            &NeverSigns,
            timestamped_settings(),
            None,
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("no time-stamp authority URL"),
            "{err}"
        );
    }
}
