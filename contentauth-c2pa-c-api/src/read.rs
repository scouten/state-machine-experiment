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

//! Read session wrapping [`FileReadSession`] for the C API.

use std::{collections::HashMap, ffi::CString};

use contentauth_c2pa_file_reader::{FileReadReply, FileReadRequest, FileReadSession, ReadReport};
use contentauth_c2pa_format_registry::AnyFormat;
use contentauth_c2pa_js_compat::{Context, ManifestStore};
use contentauth_c2pa_primitives::{Bytes, HostError};
use contentauth_sans_io_core::{RequestId, Workflow};

use crate::{error::Error, format::resolve_format, C2PA_SM_STEP_COMPLETE, C2PA_SM_STEP_PENDING};

/// Request to read bytes from asset.
pub const C2PA_SM_READ_REQ_READ: u32 = 0;
/// Request for asset total length.
pub const C2PA_SM_READ_REQ_LENGTH: u32 = 1;
/// Request for current UTC time in epoch seconds.
pub const C2PA_SM_READ_REQ_CURRENT_DATE_TIME: u32 = 2;
/// Request to perform an OCSP POST and return response DER.
pub const C2PA_SM_READ_REQ_OCSP: u32 = 3;

/// C representation of a read request.
#[repr(C)]
pub struct C2paSmReadRequest {
    /// Unique handle for fulfillment.
    pub id: u64,
    /// Request kind: `C2PA_SM_READ_REQ_*`.
    pub kind: u32,
    /// Offset for `READ`.
    pub start: u64,
    /// Byte length for `READ`.
    pub len: u64,
    /// URL for `OCSP`, or null.
    pub url: *const std::ffi::c_char,
    /// OCSP request DER bytes, or null.
    pub request_der: *const u8,
    /// Byte length of `request_der`.
    pub request_der_len: usize,
}

// These pointers refer to heap-owned request data retained by the session.
// Moving the request/session between threads does not move or invalidate it;
// callers must still honor the documented borrow lifetime when using pointers.
unsafe impl Send for C2paSmReadRequest {}

struct PendingRequestData {
    id: u64,
    kind: u32,
    start: u64,
    len: u64,
    url: Option<CString>,
    request_der: Option<Vec<u8>>,
}

/// A read session driving [`FileReadSession<AnyFormat>`].
pub struct ReadSession {
    inner: Option<FileReadSession<AnyFormat>>,
    handles: HashMap<u64, RequestId>,
    reported: HashMap<RequestId, u64>,
    next_handle: u64,
    pending_data: Vec<PendingRequestData>,
    c_requests: Vec<C2paSmReadRequest>,
    finished_report: Option<ReadReport>,
}

impl ReadSession {
    /// Creates a new read session for `format_str` with optional `settings_json`.
    pub fn new(format_str: &str, settings_json: Option<&str>) -> Result<Self, Error> {
        let format = resolve_format(format_str)?;
        let context = match settings_json {
            Some(json) if !json.trim().is_empty() => Context::from_json(json)?,
            _ => Context::default(),
        };

        Ok(Self {
            inner: Some(FileReadSession::new(&format, context.into_settings())),
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

                    let data = describe_request(handle, &request.kind)?;
                    self.pending_data.push(data);
                }

                for item in &self.pending_data {
                    self.c_requests.push(C2paSmReadRequest {
                        id: item.id,
                        kind: item.kind,
                        start: item.start,
                        len: item.len,
                        url: item
                            .url
                            .as_ref()
                            .map(|s| s.as_ptr())
                            .unwrap_or(std::ptr::null()),
                        request_der: item
                            .request_der
                            .as_ref()
                            .map(|b| b.as_ptr())
                            .unwrap_or(std::ptr::null()),
                        request_der_len: item.request_der.as_ref().map(|b| b.len()).unwrap_or(0),
                    });
                }

                Ok(C2PA_SM_STEP_PENDING)
            }
        }
    }

    /// The current slice of C requests.
    pub fn current_requests(&self) -> &[C2paSmReadRequest] {
        &self.c_requests
    }

    fn fulfill_reply(&mut self, handle: u64, reply: FileReadReply) -> Result<(), Error> {
        let engine_id = self.handles.get(&handle).copied().ok_or_else(|| {
            Error::BadParam(format!("no outstanding read request with handle {handle}"))
        })?;
        let inner = self.inner.as_mut().ok_or(Error::AlreadyFinished)?;
        inner.fulfill(engine_id, reply)?;
        self.handles.remove(&handle);
        self.reported.remove(&engine_id);
        Ok(())
    }

    /// Fulfills a read request with bytes.
    pub fn fulfill_bytes(&mut self, id: u64, bytes: &[u8]) -> Result<(), Error> {
        self.fulfill_reply(id, FileReadReply::Bytes(Bytes::copy_from_slice(bytes)))
    }

    /// Fulfills a length request with asset length.
    pub fn fulfill_length(&mut self, id: u64, length: u64) -> Result<(), Error> {
        self.fulfill_reply(id, FileReadReply::Length(length))
    }

    /// Fulfills a time request with epoch seconds.
    pub fn fulfill_time(&mut self, id: u64, epoch_secs: i64) -> Result<(), Error> {
        self.fulfill_reply(id, FileReadReply::CurrentDateTime(epoch_secs))
    }

    /// Fulfills an OCSP request with response DER bytes.
    pub fn fulfill_ocsp(&mut self, id: u64, bytes: &[u8]) -> Result<(), Error> {
        self.fulfill_reply(id, FileReadReply::OcspResponse(bytes.to_vec()))
    }

    /// Fulfills a request with a failure report.
    pub fn fulfill_failed(&mut self, id: u64, msg: &str) -> Result<(), Error> {
        self.fulfill_reply(id, FileReadReply::Failed(HostError::new(msg)))
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

    /// Finishes the read session, returning JSON and whether a manifest store was found.
    pub fn finish(&mut self) -> Result<(Option<String>, bool), Error> {
        if self.finished_report.is_some() {
            return Err(Error::AlreadyFinished);
        }
        let inner = self.inner.take().ok_or(Error::AlreadyFinished)?;
        let report = inner.finish()?;
        let found = report.manifest_store_found;
        let json = if found {
            Some(serde_json::to_string_pretty(&ManifestStore::from_report(
                &report,
            ))?)
        } else {
            None
        };
        self.finished_report = Some(report);
        Ok((json, found))
    }
}

fn describe_request(handle: u64, req: &FileReadRequest) -> Result<PendingRequestData, Error> {
    match req {
        FileReadRequest::Read { range, .. } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_READ_REQ_READ,
            start: range.start,
            len: range.len,
            url: None,
            request_der: None,
        }),
        FileReadRequest::Length { .. } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_READ_REQ_LENGTH,
            start: 0,
            len: 0,
            url: None,
            request_der: None,
        }),
        FileReadRequest::CurrentDateTime => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_READ_REQ_CURRENT_DATE_TIME,
            start: 0,
            len: 0,
            url: None,
            request_der: None,
        }),
        FileReadRequest::Ocsp { url, request_der } => Ok(PendingRequestData {
            id: handle,
            kind: C2PA_SM_READ_REQ_OCSP,
            start: 0,
            len: 0,
            url: Some(CString::new(url.as_str())?),
            request_der: Some(request_der.clone()),
        }),
        _ => Err(Error::BadParam(
            "unsupported read request variant".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn ocsp_description_preserves_url_and_der() {
        let request = FileReadRequest::Ocsp {
            url: "https://ocsp.example/".to_owned(),
            request_der: vec![0x30, 0x00],
        };
        let data = describe_request(9, &request).unwrap();
        assert_eq!(data.id, 9);
        assert_eq!(data.kind, C2PA_SM_READ_REQ_OCSP);
        assert_eq!(
            data.url.as_ref().unwrap().to_str().unwrap(),
            "https://ocsp.example/"
        );
        assert_eq!(data.request_der.unwrap(), [0x30, 0x00]);
        let invalid_url = FileReadRequest::Ocsp {
            url: "https://ocsp.example/\0".to_owned(),
            request_der: vec![],
        };
        assert!(matches!(
            describe_request(9, &invalid_url),
            Err(Error::NulError(_))
        ));
    }

    #[test]
    fn advancing_without_fulfilling_keeps_request_ids_live_without_reporting_twice() {
        let mut session = ReadSession::new("jpeg", None).unwrap();
        assert_eq!(session.advance().unwrap(), C2PA_SM_STEP_PENDING);
        let id = session.current_requests()[0].id;
        assert_eq!(session.advance().unwrap(), C2PA_SM_STEP_PENDING);
        assert!(session.current_requests().is_empty());
        assert!(session.handles.contains_key(&id));
        assert!(session.fulfill_ocsp(id, &[0x30, 0]).is_err());
        assert!(session.handles.contains_key(&id));
        assert_eq!(session.advance().unwrap(), C2PA_SM_STEP_PENDING);
        assert!(session.current_requests().is_empty());
        session
            .fulfill_failed(id, "OCSP reply had the wrong kind")
            .unwrap();
        assert!(!session.handles.contains_key(&id));
        assert!(session.fulfill_failed(id, "duplicate reply").is_err());
    }

    #[test]
    fn a_rejected_reply_can_be_corrected_without_advancing() {
        let mut session = ReadSession::new("jpeg", None).unwrap();
        session.advance().unwrap();
        let request = &session.current_requests()[0];
        let (id, kind, len) = (request.id, request.kind, request.len);
        assert!(session.fulfill_time(id, 0).is_err());
        match kind {
            C2PA_SM_READ_REQ_LENGTH => session.fulfill_length(id, 4).unwrap(),
            C2PA_SM_READ_REQ_READ => session.fulfill_bytes(id, &vec![0; len as usize]).unwrap(),
            _ => unreachable!("initial request must describe asset I/O"),
        }
        assert!(!session.handles.contains_key(&id));
    }
}
