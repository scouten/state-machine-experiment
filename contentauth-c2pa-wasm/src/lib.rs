//! Synchronous Wasm boundaries for the existing plain-data read and build sessions.

#![deny(unsafe_code, missing_docs, clippy::unwrap_used, clippy::expect_used)]

use contentauth_c2pa_session_bridge::read::{
    Error, PendingRequest, ReadSessionBridge, Reply, Step,
};
use serde_json::json;
use wasm_bindgen::prelude::*;

mod build;

fn error(err: Error) -> JsValue {
    let value = js_sys::Error::new(&err.to_string());
    value.set_name(&err.js_message());
    value.into()
}

/// A reader session owned exclusively by one browser Worker.
#[wasm_bindgen]
pub struct ReadSession(Option<ReadSessionBridge>);

#[wasm_bindgen]
impl ReadSession {
    /// Creates a session with the same settings parser as the Neon binding.
    #[wasm_bindgen(constructor)]
    pub fn new(format: &str, settings: Option<String>) -> Result<ReadSession, JsValue> {
        ReadSessionBridge::new(format, settings.as_deref())
            .map(|session| Self(Some(session)))
            .map_err(error)
    }

    /// Returns new pending requests as JSON, matching Neon's request objects.
    pub fn advance(&mut self) -> Result<String, JsValue> {
        let session = self.0.as_mut().ok_or("session already finished")?;
        let value = match session.advance().map_err(error)? {
            Step::Complete => json!({ "done": true }),
            Step::Pending(requests) => {
                let requests = requests
                    .iter()
                    .map(|request| {
                        Ok(match request {
                            PendingRequest::Read { id, start, len } => {
                                json!({ "id": id, "kind": "read", "start": start, "len": len })
                            }
                            PendingRequest::Length { id } => json!({ "id": id, "kind": "length" }),
                            PendingRequest::CurrentDateTime { id } => {
                                json!({ "id": id, "kind": "time" })
                            }
                            PendingRequest::Ocsp { .. } => {
                                return Err(JsValue::from_str(
                                    "OCSP is outside this offline proof",
                                ));
                            }
                            _ => return Err(JsValue::from_str("unsupported host request")),
                        })
                    })
                    .collect::<Result<Vec<_>, JsValue>>()?;
                json!({ "done": false, "requests": requests })
            }
        };
        Ok(value.to_string())
    }

    /// Copies the exact bytes requested by a pending read into the session.
    pub fn bytes(&mut self, id: u32, bytes: &[u8]) -> Result<(), JsValue> {
        self.reply(id, Reply::Bytes(bytes.to_vec()))
    }

    /// Answers a length request, rejecting values JavaScript cannot represent.
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

    /// Answers the host clock request with Unix seconds.
    pub fn time(&mut self, id: u32, value: i32) -> Result<(), JsValue> {
        self.reply(id, Reply::Time(i64::from(value)))
    }

    /// Consumes the completed session and returns report JSON or no store.
    pub fn finish(&mut self) -> Result<Option<String>, JsValue> {
        self.0
            .take()
            .ok_or("session already finished")?
            .finish()
            .map(|reader| reader.map(|reader| reader.json()))
            .map_err(error)
    }
}

impl ReadSession {
    fn reply(&mut self, id: u32, reply: Reply) -> Result<(), JsValue> {
        self.0
            .as_mut()
            .ok_or("session already finished")?
            .fulfill(u64::from(id), reply)
            .map_err(error)
    }
}
