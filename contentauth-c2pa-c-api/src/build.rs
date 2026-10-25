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

//! Build session wrapping [`FileBuilderSession`] for the C API.

use std::{collections::HashMap, ffi::CString};

use contentauth_c2pa_file_builder::{
    FileBuilderReply, FileBuilderReport, FileBuilderRequest, FileBuilderSession, SignPurpose,
};
use contentauth_c2pa_format_registry::AnyFormat;
use contentauth_c2pa_primitives::{
    tsa::{timestamp_request, timestamp_token},
    Bytes, HostError, SigningAlg,
};
use contentauth_c2pa_sign_baseline::Definition;
use contentauth_sans_io_core::{RequestId, Workflow};

use crate::{error::Error, format::resolve_format, C2PA_SM_STEP_COMPLETE, C2PA_SM_STEP_PENDING};

/// Input source stream identifier.
pub const C2PA_SM_STREAM_SOURCE: u32 = 0;
/// Output destination stream identifier.
pub const C2PA_SM_STREAM_OUTPUT: u32 = 1;

/// Request to read bytes from source or output.
pub const C2PA_SM_BUILD_REQ_READ: u32 = 0;
/// Request for length of source stream.
pub const C2PA_SM_BUILD_REQ_LENGTH: u32 = 1;
/// Request to write bytes to output stream.
pub const C2PA_SM_BUILD_REQ_WRITE: u32 = 2;
/// Request to sign the full COSE Sig_structure message bytes in `data`, not a digest.
///
/// Return a COSE-format signature: ECDSA uses fixed-width `r || s`, not DER.
pub const C2PA_SM_BUILD_REQ_SIGN: u32 = 3;
/// Request for RFC 3161 TSA timestamp over token request.
pub const C2PA_SM_BUILD_REQ_TIMESTAMP: u32 = 4;

/// C exclusion structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2paSmExclusion {
    /// Start offset in output.
    pub start: u64,
    /// Byte length.
    pub len: u64,
}

/// C representation of a build request.
#[repr(C)]
pub struct C2paSmBuildRequest {
    /// Unique handle for fulfillment.
    pub id: u64,
    /// Request kind: `C2PA_SM_BUILD_REQ_*`.
    pub kind: u32,
    /// Stream: `C2PA_SM_STREAM_*`.
    pub stream: u32,
    /// Offset for `READ` or `WRITE`.
    pub offset: u64,
    /// Byte length for `READ`.
    pub len: u64,
    /// Data payload for `WRITE`, `SIGN`, or `TIMESTAMP`.
    /// For `SIGN`, these are the full COSE Sig_structure message bytes, not a digest.
    pub data: *const u8,
    /// Length of `data` in bytes.
    pub data_len: usize,
    /// Signing algorithm name (e.g. "es256"), or null.
    pub alg: *const std::ffi::c_char,
    /// TSA URL for `TIMESTAMP`, or null.
    pub url: *const std::ffi::c_char,
}

// These pointers refer to heap-owned request data retained by the session.
// Moving the request/session between threads does not move or invalidate it;
// callers must still honor the documented borrow lifetime when using pointers.
unsafe impl Send for C2paSmBuildRequest {}

struct PendingRequestData {
    id: u64,
    kind: u32,
    stream: u32,
    offset: u64,
    len: u64,
    data: Option<Bytes>,
    alg: Option<CString>,
    url: Option<CString>,
}

/// A build session driving [`FileBuilderSession<AnyFormat>`].
pub struct BuildSession {
    inner: Option<FileBuilderSession<AnyFormat>>,
    tsa_url: Option<String>,
    handles: HashMap<u64, RequestId>,
    reported: HashMap<RequestId, u64>,
    next_handle: u64,
    pending_data: Vec<PendingRequestData>,
    c_requests: Vec<C2paSmBuildRequest>,
    finished_report: Option<FileBuilderReport>,
}

impl BuildSession {
    /// Starts a build session for `format_str` with `definition_json`, `alg_str`, and DER `certs`.
    pub fn new(
        format_str: &str,
        definition_json: &str,
        alg_str: &str,
        certs: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        let format = resolve_format(format_str)?;
        let alg = parse_alg(alg_str)?;
        let definition = Definition::from_json(definition_json)?;
        let tsa_url = definition.tsa_url.clone();
        let settings = definition.into_settings(alg, certs)?;

        Ok(Self {
            inner: Some(FileBuilderSession::new(format, settings)),
            tsa_url,
            handles: HashMap::new(),
            reported: HashMap::new(),
            next_handle: 0,
            pending_data: Vec::new(),
            c_requests: Vec::new(),
            finished_report: None,
        })
    }

    /// Advances the session.
    pub fn advance(&mut self) -> Result<i32, Error> {
        use contentauth_sans_io_core::Step as Engine;

        let inner = self.inner.as_mut().ok_or(Error::AlreadyFinished)?;

        match inner.advance()? {
            Engine::Complete => Ok(C2PA_SM_STEP_COMPLETE),
            _ => {
                self.pending_data.clear();
                self.c_requests.clear();

                for request in inner.outstanding_requests() {
                    if self.reported.contains_key(&request.id) {
                        continue;
                    }
                    let handle = self.next_handle;
                    self.next_handle += 1;
                    self.reported.insert(request.id, handle);
                    self.handles.insert(handle, request.id);

                    let data = describe_request(handle, &request.kind, self.tsa_url.as_deref())?;
                    self.pending_data.push(data);
                }

                for item in &self.pending_data {
                    self.c_requests.push(C2paSmBuildRequest {
                        id: item.id,
                        kind: item.kind,
                        stream: item.stream,
                        offset: item.offset,
                        len: item.len,
                        data: item
                            .data
                            .as_ref()
                            .map(|b| b.as_ptr())
                            .unwrap_or(std::ptr::null()),
                        data_len: item.data.as_ref().map(|b| b.len()).unwrap_or(0),
                        alg: item
                            .alg
                            .as_ref()
                            .map(|s| s.as_ptr())
                            .unwrap_or(std::ptr::null()),
                        url: item
                            .url
                            .as_ref()
                            .map(|s| s.as_ptr())
                            .unwrap_or(std::ptr::null()),
                    });
                }

                Ok(C2PA_SM_STEP_PENDING)
            }
        }
    }

    /// Current slice of C build requests.
    pub fn current_requests(&self) -> &[C2paSmBuildRequest] {
        &self.c_requests
    }

    fn engine_id(&self, handle: u64) -> Result<RequestId, Error> {
        self.handles.get(&handle).copied().ok_or_else(|| {
            Error::BadParam(format!("no outstanding build request with handle {handle}"))
        })
    }

    fn fulfill_reply(&mut self, handle: u64, reply: FileBuilderReply) -> Result<(), Error> {
        let engine_id = self.engine_id(handle)?;
        let inner = self.inner.as_mut().ok_or(Error::AlreadyFinished)?;
        inner.fulfill(engine_id, reply)?;
        self.handles.remove(&handle);
        self.reported.remove(&engine_id);
        Ok(())
    }

    /// Fulfills a read request.
    pub fn fulfill_bytes(&mut self, id: u64, bytes: &[u8]) -> Result<(), Error> {
        self.fulfill_reply(id, FileBuilderReply::Bytes(Bytes::copy_from_slice(bytes)))
    }

    /// Fulfills a length request.
    pub fn fulfill_length(&mut self, id: u64, length: u64) -> Result<(), Error> {
        self.fulfill_reply(id, FileBuilderReply::Length(length))
    }

    /// Fulfills a write request.
    pub fn fulfill_written(&mut self, id: u64) -> Result<(), Error> {
        self.fulfill_reply(id, FileBuilderReply::Written)
    }

    /// Fulfills a sign request with COSE-format signature bytes.
    /// ECDSA signatures must be fixed-width `r || s`, not DER.
    pub fn fulfill_signature(&mut self, id: u64, sig: &[u8]) -> Result<(), Error> {
        self.fulfill_reply(id, FileBuilderReply::Signature(sig.to_vec()))
    }

    /// Fulfills a timestamp request with DER TimeStampResp bytes.
    pub fn fulfill_timestamp(&mut self, id: u64, resp: &[u8]) -> Result<(), Error> {
        self.engine_id(id)?;
        let token = timestamp_token(resp)
            .map_err(|err| Error::BadParam(format!("invalid timestamp response: {err}")))?;
        self.fulfill_reply(id, FileBuilderReply::Timestamp(token))
    }

    /// Fulfills a request with a failure report.
    pub fn fulfill_failed(&mut self, id: u64, msg: &str) -> Result<(), Error> {
        self.fulfill_reply(id, FileBuilderReply::Failed(HostError::new(msg)))
    }

    /// Where the underlying session is — the phase it is waiting in, or
    /// the one it failed in — for diagnostics only; `"Finished"` once
    /// [`Self::finish`] has consumed it. See
    /// [`contentauth_sans_io_core::Workflow::phase`].
    pub fn phase(&self) -> String {
        self.inner
            .as_ref()
            .map_or_else(|| "Finished".to_owned(), Workflow::phase)
    }

    /// Finishes the build session.
    pub fn finish(&mut self) -> Result<(Vec<u8>, Vec<C2paSmExclusion>), Error> {
        if self.finished_report.is_some() {
            return Err(Error::AlreadyFinished);
        }
        let inner = self.inner.take().ok_or(Error::AlreadyFinished)?;
        let report = inner.finish()?;
        let exclusions = report
            .exclusions
            .iter()
            .map(|r| C2paSmExclusion {
                start: r.start,
                len: r.len,
            })
            .collect();
        let manifest = report.manifest.clone();
        self.finished_report = Some(report);
        Ok((manifest.to_vec(), exclusions))
    }
}

fn describe_request(
    handle: u64,
    req: &FileBuilderRequest,
    tsa_url: Option<&str>,
) -> Result<PendingRequestData, Error> {
    match req {
        FileBuilderRequest::Read { stream, range } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_BUILD_REQ_READ,
            stream: map_stream(*stream),
            offset: range.start,
            len: range.len,
            data: None,
            alg: None,
            url: None,
        }),
        FileBuilderRequest::Length { stream } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_BUILD_REQ_LENGTH,
            stream: map_stream(*stream),
            offset: 0,
            len: 0,
            data: None,
            alg: None,
            url: None,
        }),
        FileBuilderRequest::Write {
            stream,
            offset,
            bytes,
        } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_BUILD_REQ_WRITE,
            stream: map_stream(*stream),
            offset: *offset,
            len: bytes.len() as u64,
            data: Some(bytes.clone()),
            alg: None,
            url: None,
        }),
        FileBuilderRequest::Sign {
            purpose: SignPurpose::Claim,
            alg,
            data,
        } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_BUILD_REQ_SIGN,
            stream: C2PA_SM_STREAM_OUTPUT,
            offset: 0,
            len: 0,
            data: Some(Bytes::copy_from_slice(data)),
            alg: Some(CString::new(alg_name(*alg)?)?),
            url: None,
        }),
        FileBuilderRequest::Sign { purpose, .. } => Err(Error::BadParam(format!(
            "unsupported sign purpose: {purpose:?}"
        ))),
        FileBuilderRequest::Timestamp { digest, hash_alg } => {
            let url = tsa_url.ok_or_else(|| {
                Error::BadParam("timestamp requested but no tsa_url configured".to_string())
            })?;
            let request = timestamp_request(digest, *hash_alg)
                .map_err(|err| Error::BadParam(format!("timestamp request build error: {err}")))?;
            Ok(PendingRequestData {
                id: handle,
                kind: C2PA_SM_BUILD_REQ_TIMESTAMP,
                stream: C2PA_SM_STREAM_OUTPUT,
                offset: 0,
                len: 0,
                data: Some(request.into()),
                alg: None,
                url: Some(CString::new(url)?),
            })
        }
        _ => Err(Error::BadParam(
            "unsupported build request variant".to_string(),
        )),
    }
}

fn map_stream(stream: contentauth_c2pa_primitives::StreamId) -> u32 {
    if stream == FileBuilderSession::<AnyFormat>::SOURCE_STREAM {
        C2PA_SM_STREAM_SOURCE
    } else {
        C2PA_SM_STREAM_OUTPUT
    }
}

fn parse_alg(alg: &str) -> Result<SigningAlg, Error> {
    match alg.to_ascii_lowercase().as_str() {
        "es256" => Ok(SigningAlg::Es256),
        "es384" => Ok(SigningAlg::Es384),
        "es512" => Ok(SigningAlg::Es512),
        "ps256" => Ok(SigningAlg::Ps256),
        "ps384" => Ok(SigningAlg::Ps384),
        "ps512" => Ok(SigningAlg::Ps512),
        "ed25519" => Ok(SigningAlg::Ed25519),
        _ => Err(Error::BadParam(format!(
            "unsupported signing algorithm: {alg}"
        ))),
    }
}

fn alg_name(alg: SigningAlg) -> Result<&'static str, Error> {
    match alg {
        SigningAlg::Es256 => Ok("es256"),
        SigningAlg::Es384 => Ok("es384"),
        SigningAlg::Es512 => Ok("es512"),
        SigningAlg::Ps256 => Ok("ps256"),
        SigningAlg::Ps384 => Ok("ps384"),
        SigningAlg::Ps512 => Ok("ps512"),
        SigningAlg::Ed25519 => Ok("ed25519"),
        _ => Err(Error::BadParam(format!("unsupported algorithm {alg:?}"))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use contentauth_c2pa_primitives::HashAlgorithm;

    use super::*;

    #[test]
    fn algorithm_names_round_trip_and_unknown_names_fail() {
        for (name, alg) in [
            ("es256", SigningAlg::Es256),
            ("es384", SigningAlg::Es384),
            ("es512", SigningAlg::Es512),
            ("ps256", SigningAlg::Ps256),
            ("ps384", SigningAlg::Ps384),
            ("ps512", SigningAlg::Ps512),
            ("ed25519", SigningAlg::Ed25519),
        ] {
            assert_eq!(parse_alg(&name.to_uppercase()).unwrap(), alg);
            assert_eq!(alg_name(alg).unwrap(), name);
        }
        assert!(matches!(parse_alg("unknown"), Err(Error::BadParam(_))));
    }

    #[test]
    fn timestamp_description_requires_a_url_and_preserves_request_data() {
        let request = FileBuilderRequest::Timestamp {
            digest: vec![0x42; 32],
            hash_alg: HashAlgorithm::Sha256,
        };
        assert!(matches!(
            describe_request(4, &request, None),
            Err(Error::BadParam(_))
        ));
        let data = describe_request(4, &request, Some("https://tsa.example/")).unwrap();
        assert_eq!(data.id, 4);
        assert_eq!(data.kind, C2PA_SM_BUILD_REQ_TIMESTAMP);
        assert_eq!(
            data.url.as_ref().unwrap().to_str().unwrap(),
            "https://tsa.example/"
        );
        assert_eq!(
            data.data.unwrap(),
            timestamp_request(&[0x42; 32], HashAlgorithm::Sha256).unwrap()
        );
        assert!(matches!(
            describe_request(4, &request, Some("https://tsa.example/\0")),
            Err(Error::NulError(_))
        ));
        let bad_digest = FileBuilderRequest::Timestamp {
            digest: vec![0x42; 31],
            hash_alg: HashAlgorithm::Sha256,
        };
        let error = describe_request(4, &bad_digest, Some("https://tsa.example/"));
        assert!(
            matches!(error, Err(Error::BadParam(message)) if message.contains("timestamp request build error"))
        );
    }

    #[test]
    fn identity_signing_is_explicitly_rejected_instead_of_using_the_claim_key() {
        let request = FileBuilderRequest::Sign {
            purpose: SignPurpose::Identity {
                label: "cawg.identity".to_owned(),
            },
            alg: SigningAlg::Es256,
            data: vec![1, 2, 3],
        };
        assert!(matches!(
            describe_request(7, &request, None),
            Err(Error::BadParam(message)) if message.contains("unsupported sign purpose") && message.contains("cawg.identity")
        ));
    }

    #[test]
    fn advancing_without_fulfilling_does_not_duplicate_pending_requests() {
        let mut session = BuildSession::new(
            "jpeg",
            contentauth_c2pa_sign_baseline::BASELINE_DEFINITION,
            "es256",
            vec![contentauth_c2pa_sign_baseline::fixtures::TEST_SIGNER_CERT.to_vec()],
        )
        .unwrap();
        assert_eq!(session.advance().unwrap(), C2PA_SM_STEP_PENDING);
        assert!(!session.current_requests().is_empty());
        let id = session.current_requests()[0].id;
        assert_eq!(session.advance().unwrap(), C2PA_SM_STEP_PENDING);
        assert!(session.current_requests().is_empty());
        assert!(session.handles.contains_key(&id));
        session.fulfill_failed(id, "host unavailable").unwrap();
        assert!(session.advance().is_err());
    }

    #[test]
    fn rejected_replies_can_be_corrected_without_advancing() {
        let mut session = BuildSession::new(
            "jpeg",
            contentauth_c2pa_sign_baseline::BASELINE_DEFINITION,
            "es256",
            vec![contentauth_c2pa_sign_baseline::fixtures::TEST_SIGNER_CERT.to_vec()],
        )
        .unwrap();
        session.advance().unwrap();
        let request = &session.current_requests()[0];
        let (id, kind, len) = (request.id, request.kind, request.len);
        assert!(session.fulfill_signature(id, &[0]).is_err());
        assert!(session.fulfill_written(id).is_err());
        assert!(session.fulfill_timestamp(id, &[0]).is_err());
        assert!(session.handles.contains_key(&id));
        match kind {
            C2PA_SM_BUILD_REQ_LENGTH => session.fulfill_length(id, 4).unwrap(),
            C2PA_SM_BUILD_REQ_READ => session.fulfill_bytes(id, &vec![0; len as usize]).unwrap(),
            _ => unreachable!("initial request must describe asset I/O"),
        }
        assert!(!session.handles.contains_key(&id));
        assert!(session.fulfill_failed(id, "duplicate reply").is_err());
    }
}
