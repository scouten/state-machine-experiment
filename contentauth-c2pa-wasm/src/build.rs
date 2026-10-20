use contentauth_c2pa_session_bridge::build::{
    BuildSessionBridge, Error, IdentitySigner, PendingRequest, Reply, Step,
};
use serde_json::json;
use wasm_bindgen::prelude::*;

fn error(err: Error) -> JsValue {
    let value = js_sys::Error::new(&err.to_string());
    value.set_name(&err.js_message());
    value.into()
}

/// One CAWG identity as JavaScript describes it.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityJson {
    alg: String,
    certs: Vec<Vec<u8>>,
    #[serde(default)]
    roles: Vec<String>,
    referenced_assertions: Option<Vec<String>>,
}

/// A build session owned by one browser Worker.
#[wasm_bindgen]
pub struct BuildSession {
    inner: Option<BuildSessionBridge>,
    payloads: Vec<Option<Vec<u8>>>,
}

#[wasm_bindgen]
impl BuildSession {
    /// Creates the existing builder with public certificate bytes, never a key.
    #[wasm_bindgen(constructor)]
    pub fn new(
        definition: &str,
        format: &str,
        alg: &str,
        certs_json: &str,
        identities_json: &str,
    ) -> Result<BuildSession, JsValue> {
        let certs = serde_json::from_str(certs_json)
            .map_err(|err| JsValue::from_str(&format!("invalid certificate list: {err}")))?;
        let identities: Vec<IdentityJson> = serde_json::from_str(identities_json)
            .map_err(|err| JsValue::from_str(&format!("invalid identity list: {err}")))?;
        let identities = identities
            .into_iter()
            .map(|identity| IdentitySigner {
                alg: identity.alg,
                certs: identity.certs,
                roles: identity.roles,
                referenced_assertions: identity.referenced_assertions,
            })
            .collect();
        BuildSessionBridge::new(definition, format, alg, certs, identities)
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
                    .iter()
                    .map(|request| {
                        Ok(match request {
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
                                    self.payloads.push(Some(bytes.clone()));
                                    json!({ "id": id, "kind": "write", "stream": stream.as_str(),
                                        "offset": offset, "payload": payload })
                                } else {
                                    json!({ "id": id, "kind": "write", "stream": stream.as_str(),
                                        "offset": offset, "bytes": bytes })
                                }
                            }
                            PendingRequest::Sign { id, alg, data, identity } => {
                                json!({ "id": id, "kind": "sign", "alg": alg, "data": data, "identity": identity })
                            }
                            _ => return Err(JsValue::from_str("unsupported build host request")),
                        })
                    })
                    .collect::<Result<Vec<_>, JsValue>>()?;
                json!({ "done": false, "requests": requests })
            }
        };
        Ok(value.to_string())
    }

    /// Consumes one write payload as bytes copied by wasm-bindgen, not JSON.
    pub fn payload(&mut self, index: u32) -> Result<Vec<u8>, JsValue> {
        self.payloads
            .get_mut(index as usize)
            .and_then(Option::take)
            .ok_or_else(|| JsValue::from_str("unknown or consumed write payload"))
    }

    /// Answers a source or output byte-range read.
    pub fn bytes(&mut self, id: u32, bytes: &[u8]) -> Result<(), JsValue> {
        self.reply(id, Reply::Bytes(bytes.to_vec()))
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

    /// Supplies the caller-produced raw signature.
    pub fn signature(&mut self, id: u32, bytes: &[u8]) -> Result<(), JsValue> {
        self.reply(id, Reply::Signature(bytes.to_vec()))
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
        Ok(json!({ "manifest": report.manifest, "exclusions": exclusions }).to_string())
    }
}

impl BuildSession {
    fn reply(&mut self, id: u32, reply: Reply) -> Result<(), JsValue> {
        self.inner
            .as_mut()
            .ok_or("session already finished")?
            .fulfill(u64::from(id), reply)
            .map_err(error)
    }
}
