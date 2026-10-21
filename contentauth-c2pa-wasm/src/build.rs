use contentauth_c2pa_session_bridge::{
    Bytes,
    build::{BuildSessionBridge, Error, PendingRequest, Reply, Step},
};
use serde_json::json;
use wasm_bindgen::prelude::*;

fn error(err: Error) -> JsValue {
    let value = js_sys::Error::new(&err.to_string());
    value.set_name(&err.js_message());
    value.into()
}

/// A baseline ES256 JPEG build session owned by one browser Worker.
#[wasm_bindgen]
pub struct BuildSession {
    inner: Option<BuildSessionBridge>,
    payloads: Vec<Option<Bytes>>,
}

#[wasm_bindgen]
impl BuildSession {
    /// Creates the existing builder with public certificate bytes, never a key.
    #[wasm_bindgen(constructor)]
    pub fn new(definition: &str, certs_json: &str) -> Result<BuildSession, JsValue> {
        let certs = serde_json::from_str(certs_json)
            .map_err(|err| JsValue::from_str(&format!("invalid certificate list: {err}")))?;
        BuildSessionBridge::new(definition, "image/jpeg", "es256", certs)
            .map(|session| Self {
                inner: Some(session),
                payloads: Vec::new(),
            })
            .map_err(error)
    }

    /// Returns request metadata as JSON, optionally separating binary write bytes.
    ///
    /// `false` retains the original JSON byte-array boundary as an experiment
    /// control. With `true`, each write names a payload consumed by `payload`.
    pub fn advance(&mut self, binary: bool) -> Result<String, JsValue> {
        if self.payloads.iter().any(Option::is_some) {
            return Err(JsValue::from_str("unconsumed write payload"));
        }
        self.payloads.clear();
        let session = self.inner.as_mut().ok_or("session already finished")?;
        let value = match session.advance().map_err(error)? {
            Step::Complete => json!({ "done": true }),
            Step::Pending(requests) => {
                let requests = requests
                    .into_iter()
                    .map(|request| self.describe(request, binary))
                    .collect::<Result<Vec<_>, JsValue>>()?;
                json!({ "done": false, "requests": requests })
            }
        };
        Ok(value.to_string())
    }

    /// Consumes one write payload as bytes copied by wasm-bindgen, not JSON.
    pub fn payload(&mut self, index: u32) -> Result<js_sys::Uint8Array, JsValue> {
        let bytes = self.take_payload(index)?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Answers a source or output byte-range read.
    pub fn bytes(&mut self, id: u32, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.reply(id, Reply::Bytes(bytes))
    }

    /// Reports a stream length exactly representable by JavaScript.
    pub fn length(&mut self, id: u32, value: f64) -> Result<(), JsValue> {
        if !value.is_finite()
            || value < 0.0
            || value.fract() != 0.0
            || value > 9_007_199_254_740_991.0
        {
            return Err(JsValue::from_str("invalid asset length"));
        }
        self.reply(id, Reply::Length(value as u64))
    }

    /// Confirms an output write is visible to subsequent reads.
    pub fn written(&mut self, id: u32) -> Result<(), JsValue> {
        self.reply(id, Reply::Written)
    }

    /// Confirms every copied byte is visible to subsequent output reads.
    pub fn copied(&mut self, id: u32) -> Result<(), JsValue> {
        self.reply(id, Reply::Copied)
    }

    /// Supplies the caller-produced raw signature.
    pub fn signature(&mut self, id: u32, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.reply(id, Reply::Signature(bytes))
    }

    /// Consumes the session and returns manifest bytes and exclusion ranges.
    pub fn finish(&mut self) -> Result<String, JsValue> {
        let report = self
            .inner
            .take()
            .ok_or("session already finished")?
            .finish()
            .map_err(error)?;
        let exclusions = report
            .exclusions
            .iter()
            .map(|range| json!({ "start": range.start, "len": range.len }))
            .collect::<Vec<_>>();
        Ok(json!({ "manifest": &report.manifest[..], "exclusions": exclusions }).to_string())
    }
}

impl BuildSession {
    fn take_payload(&mut self, index: u32) -> Result<Bytes, JsValue> {
        self.payloads
            .get_mut(index as usize)
            .and_then(Option::take)
            .ok_or_else(|| JsValue::from_str("unknown or consumed write payload"))
    }

    fn describe(
        &mut self,
        request: PendingRequest,
        binary: bool,
    ) -> Result<serde_json::Value, JsValue> {
        Ok(match request {
            PendingRequest::CopyRange {
                id,
                start,
                len,
                offset,
            } => {
                json!({ "id": id, "kind": "copyRange", "start": start, "len": len, "offset": offset })
            }
            PendingRequest::Read {
                id,
                stream,
                start,
                len,
            } => json!({ "id": id, "kind": "read", "stream": stream.as_str(),
                "start": start, "len": len }),
            PendingRequest::Length { id, stream } => {
                json!({ "id": id, "kind": "length", "stream": stream.as_str() })
            }
            PendingRequest::Write {
                id,
                stream,
                offset,
                bytes,
            } => {
                if binary {
                    let payload = self.payloads.len();
                    self.payloads.push(Some(bytes));
                    json!({ "id": id, "kind": "write", "stream": stream.as_str(),
                        "offset": offset, "payload": payload })
                } else {
                    json!({ "id": id, "kind": "write", "stream": stream.as_str(),
                        "offset": offset, "bytes": &bytes[..] })
                }
            }
            PendingRequest::Sign { id, alg, data } => {
                json!({ "id": id, "kind": "sign", "alg": alg, "data": data })
            }
            _ => return Err(JsValue::from_str("unsupported build host request")),
        })
    }

    fn reply(&mut self, id: u32, reply: Reply) -> Result<(), JsValue> {
        self.inner
            .as_mut()
            .ok_or("session already finished")?
            .fulfill(u64::from(id), reply)
            .map_err(error)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use contentauth_c2pa_session_bridge::build::Stream;

    use super::*;

    fn session() -> BuildSession {
        BuildSession {
            inner: None,
            payloads: Vec::new(),
        }
    }

    fn write(id: u64, bytes: Bytes) -> PendingRequest {
        PendingRequest::Write {
            id,
            stream: Stream::Output,
            offset: 9,
            bytes,
        }
    }

    #[test]
    fn copy_ranges_have_only_metadata_in_both_transports() {
        for binary in [false, true] {
            let mut session = session();
            let request = session
                .describe(
                    PendingRequest::CopyRange {
                        id: 7,
                        start: 10,
                        len: 100,
                        offset: 30,
                    },
                    binary,
                )
                .unwrap();
            assert_eq!(
                request,
                json!({
                    "id": 7, "kind": "copyRange", "start": 10, "len": 100, "offset": 30,
                })
            );
            assert!(session.payloads.is_empty());
        }
    }

    #[test]
    fn binary_writes_retain_shared_storage_until_each_payload_is_consumed() {
        let mut session = session();
        let bytes = Bytes::from(vec![0x42; 128 * 1024]);
        for index in 0..2 {
            let request = session.describe(write(index, bytes.clone()), true).unwrap();
            assert_eq!(
                request,
                json!({ "id": index, "kind": "write", "stream": "output",
                    "offset": 9, "payload": index })
            );
            assert_eq!(
                session.payloads[index as usize].as_ref().unwrap().as_ptr(),
                bytes.as_ptr()
            );
        }
        for index in 0..2 {
            let payload = session.take_payload(index).unwrap();
            assert_eq!(payload.as_ptr(), bytes.as_ptr());
            assert_eq!(payload, bytes);
            assert!(session.payloads[index as usize].is_none());
        }
    }

    #[test]
    fn json_writes_keep_byte_arrays_and_do_not_queue_binary_payloads() {
        let mut session = session();
        for bytes in [Bytes::from_static(&[1, 2, 255]), Bytes::new()] {
            let request = session.describe(write(7, bytes.clone()), false).unwrap();
            assert_eq!(
                request,
                json!({ "id": 7, "kind": "write", "stream": "output",
                    "offset": 9, "bytes": &bytes[..] })
            );
            assert!(session.payloads.is_empty());
        }
    }

    #[test]
    fn empty_binary_writes_still_have_a_consumable_payload() {
        let mut session = session();
        let request = session.describe(write(7, Bytes::new()), true).unwrap();
        assert_eq!(request["payload"], 0);
        assert!(session.take_payload(0).unwrap().is_empty());
        assert!(session.payloads[0].is_none());
    }

    #[test]
    fn non_write_request_metadata_is_unchanged_in_either_mode() {
        let mut session = session();
        for binary in [false, true] {
            assert_eq!(
                session
                    .describe(
                        PendingRequest::Read {
                            id: 1,
                            stream: Stream::Source,
                            start: 3,
                            len: 5,
                        },
                        binary,
                    )
                    .unwrap(),
                json!({ "id": 1, "kind": "read", "stream": "source", "start": 3, "len": 5 })
            );
            assert_eq!(
                session
                    .describe(
                        PendingRequest::Length {
                            id: 2,
                            stream: Stream::Source,
                        },
                        binary,
                    )
                    .unwrap(),
                json!({ "id": 2, "kind": "length", "stream": "source" })
            );
            assert_eq!(
                session
                    .describe(
                        PendingRequest::Sign {
                            id: 3,
                            alg: "es256",
                            data: vec![4, 5],
                        },
                        binary,
                    )
                    .unwrap(),
                json!({ "id": 3, "kind": "sign", "alg": "es256", "data": [4, 5] })
            );
            assert!(session.payloads.is_empty());
        }
    }
}
