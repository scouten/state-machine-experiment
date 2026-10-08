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

//! [`NodeBuildSession`]: the synchronous surface Node drives.

use std::collections::HashMap;

use contentauth_c2pa_file_builder::{
    FileBuilderReply, FileBuilderRequest, FileBuilderSession, SignPurpose,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_js_compat::{for_format, C2paError};
use contentauth_c2pa_primitives::{
    tsa::{timestamp_request, timestamp_token},
    HostError, SigningAlg,
};
use contentauth_c2pa_sign_baseline::Definition;
use contentauth_state_machine::{RequestId, Session};

use crate::Error;

type Engine = FileBuilderSession<JpegFormat>;

/// Which of the two assets a request concerns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    /// The asset being signed. Read-only.
    Source,
    /// The asset being assembled. Written, then read back for hashing.
    Output,
}

impl Stream {
    /// The name JavaScript sees: `"source"` or `"output"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Output => "output",
        }
    }

    fn from_engine(stream: contentauth_c2pa_primitives::StreamId) -> Result<Self, Error> {
        if stream == Engine::SOURCE_STREAM {
            Ok(Self::Source)
        } else if stream == Engine::OUTPUT_STREAM {
            Ok(Self::Output)
        } else {
            Err(Error::Unsupported(format!("unknown stream {stream:?}")))
        }
    }
}

/// One thing the session needs its host to do, as plain data.
///
/// `id` is what to quote back to [`NodeBuildSession::fulfill`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PendingRequest {
    /// Read exactly `len` bytes of `stream` starting at `start`.
    /// Answer with [`Reply::Bytes`].
    Read {
        /// The handle to pass to [`NodeBuildSession::fulfill`].
        id: u64,
        /// Which asset.
        stream: Stream,
        /// Offset of the first byte.
        start: u64,
        /// Number of bytes.
        len: u64,
    },

    /// Report the total length of `stream`. Answer with [`Reply::Length`].
    Length {
        /// The handle to pass to [`NodeBuildSession::fulfill`].
        id: u64,
        /// Which asset.
        stream: Stream,
    },

    /// Write `bytes` at `offset` of `stream` (always the output today).
    /// Answer with [`Reply::Written`] once a later read would see them.
    Write {
        /// The handle to pass to [`NodeBuildSession::fulfill`].
        id: u64,
        /// Which asset.
        stream: Stream,
        /// Offset to write at.
        offset: u64,
        /// The bytes.
        bytes: Vec<u8>,
    },

    /// Sign `data` (a COSE `Sig_structure`) with `alg` and answer with
    /// [`Reply::Signature`]: for ECDSA the raw fixed-width `r || s`, not DER.
    Sign {
        /// The handle to pass to [`NodeBuildSession::fulfill`].
        id: u64,
        /// The algorithm, lower-case: `"es256"`, `"ps256"`, `"ed25519"`...
        alg: &'static str,
        /// The bytes to sign.
        data: Vec<u8>,
    },

    /// `POST` `request` to the time-stamp authority at `url`, with
    /// `Content-Type: application/timestamp-query`, and answer with the
    /// response body, unread, as [`Reply::TimestampResponse`].
    ///
    /// `request` is a complete DER `TimeStampReq`; Rust has already built
    /// it and will unwrap the token from the response, so the host needs
    /// no RFC 3161 knowledge — only an HTTP client. `url` is the
    /// definition's `tsa_url`.
    Timestamp {
        /// The handle to pass to [`NodeBuildSession::fulfill`].
        id: u64,
        /// The authority's URL (`http` or `https`).
        url: String,
        /// The DER `TimeStampReq` to send as the body.
        request: Vec<u8>,
    },
}

impl PendingRequest {
    /// The handle to pass to [`NodeBuildSession::fulfill`].
    pub fn id(&self) -> u64 {
        match self {
            Self::Read { id, .. }
            | Self::Length { id, .. }
            | Self::Write { id, .. }
            | Self::Sign { id, .. }
            | Self::Timestamp { id, .. } => *id,
        }
    }
}

/// The host's answer to one [`PendingRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    /// The bytes a [`PendingRequest::Read`] asked for.
    Bytes(Vec<u8>),
    /// A stream's length in bytes.
    Length(u64),
    /// A [`PendingRequest::Write`] is done.
    Written,
    /// The signature a [`PendingRequest::Sign`] asked for.
    Signature(Vec<u8>),
    /// The body the time-stamp authority answered a
    /// [`PendingRequest::Timestamp`] with: a DER `TimeStampResp`, exactly
    /// as received. A refusal in it fails the build.
    TimestampResponse(Vec<u8>),
    /// The host could not do it (a rejected signer, an I/O error). Valid
    /// for any request; the build fails.
    Failed(String),
}

/// What [`NodeBuildSession::advance`] reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Not finished. The vector holds the requests that are *new* since
    /// the last call — possibly none, if the session is still waiting on
    /// requests already reported.
    Pending(Vec<PendingRequest>),

    /// Finished; call [`NodeBuildSession::finish`].
    Complete,
}

/// What a finished build reports. The signed asset itself is not here:
/// every byte of it already went to the host as a [`PendingRequest::Write`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignReport {
    /// The manifest store's bytes, as embedded.
    pub manifest: Vec<u8>,
    /// The hard binding's exclusions, ascending: the container structure
    /// carrying the manifest, framing included, and anything else the
    /// format's specification excludes (TIFF excludes a length field apart
    /// from the store).
    pub exclusions: Vec<Exclusion>,
}

/// One range of the output the hard binding excludes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exclusion {
    /// Offset in the output.
    pub start: u64,
    /// Length in bytes.
    pub len: u64,
}

/// A signing of one asset, driven entirely by its caller.
///
/// A thin, FFI-shaped wrapper over [`FileBuilderSession`]: it never
/// blocks, never spawns, holds no lock, and never sees a key.
pub struct NodeBuildSession {
    inner: Engine,

    /// The definition's `tsa_url`: where a timestamp request goes.
    tsa_url: Option<String>,

    /// Numbers handed to the host, mapped to the engine's own ids.
    handles: HashMap<u64, RequestId>,
    next_handle: u64,

    /// Engine ids already reported by a previous `advance`, so each
    /// request is surfaced to the host exactly once.
    reported: HashMap<RequestId, u64>,
}

impl NodeBuildSession {
    /// Starts signing an asset of type `format` (a MIME type or bare
    /// extension) per `definition_json` (see [`Definition`]), with
    /// algorithm `alg` (`"es256"`, ...) and the DER certificate chain
    /// `certs`, signer's own first.
    ///
    /// Fails before any request is made.
    pub fn new(
        definition_json: &str,
        format: &str,
        alg: &str,
        certs: Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        for_format(format)?;
        let alg = parse_alg(alg)?;
        let definition = Definition::from_json(definition_json)?;
        let tsa_url = definition.tsa_url.clone();
        let settings = definition.into_settings(alg, certs)?;

        Ok(Self {
            inner: FileBuilderSession::new(JpegFormat, settings),
            tsa_url,
            handles: HashMap::new(),
            next_handle: 0,
            reported: HashMap::new(),
        })
    }

    /// Runs the engine as far as it can go without the host.
    pub fn advance(&mut self) -> Result<Step, Error> {
        use contentauth_state_machine::Step as Engine;

        match self.inner.advance().map_err(Error::from)? {
            Engine::Complete => Ok(Step::Complete),
            _ => {
                let mut fresh = Vec::new();
                for request in self.inner.outstanding_requests() {
                    if self.reported.contains_key(&request.id) {
                        continue;
                    }
                    let handle = self.next_handle;
                    let pending = describe(handle, &request.kind, self.tsa_url.as_deref())?;
                    self.next_handle += 1;
                    self.reported.insert(request.id, handle);
                    self.handles.insert(handle, request.id);
                    fresh.push(pending);
                }
                Ok(Step::Pending(fresh))
            }
        }
    }

    /// Reports the outcome of one pending request. Replies may arrive in
    /// any order and any subset between calls to [`Self::advance`].
    ///
    /// Fails if `id` was never issued, was already answered, or `reply`
    /// is the wrong kind for it.
    pub fn fulfill(&mut self, id: u64, reply: Reply) -> Result<(), Error> {
        let engine_id = *self.handles.get(&id).ok_or_else(|| {
            C2paError::BadParam(format!("no outstanding request with handle {id}"))
        })?;

        self.inner
            .fulfill(engine_id, engine_reply(reply)?)
            .map_err(Error::from)?;
        // Answered: forget it rather than keep an entry per request.
        self.handles.remove(&id);
        self.reported.remove(&engine_id);
        Ok(())
    }

    /// Consumes the finished session.
    pub fn finish(self) -> Result<SignReport, Error> {
        let report = self.inner.finish().map_err(Error::from)?;
        Ok(SignReport {
            manifest: report.manifest,
            exclusions: report
                .exclusions
                .iter()
                .map(|range| Exclusion {
                    start: range.start,
                    len: range.len,
                })
                .collect(),
        })
    }
}

/// Parses a signing algorithm name, case-insensitively, as c2pa-rs's JSON
/// spells it (`"es256"`).
fn parse_alg(alg: &str) -> Result<SigningAlg, C2paError> {
    Ok(match alg.to_ascii_lowercase().as_str() {
        "es256" => SigningAlg::Es256,
        "es384" => SigningAlg::Es384,
        "es512" => SigningAlg::Es512,
        "ps256" => SigningAlg::Ps256,
        "ps384" => SigningAlg::Ps384,
        "ps512" => SigningAlg::Ps512,
        "ed25519" => SigningAlg::Ed25519,
        other => return Err(C2paError::BadParam(format!("unknown algorithm {other:?}"))),
    })
}

fn alg_name(alg: SigningAlg) -> Result<&'static str, Error> {
    Ok(match alg {
        SigningAlg::Es256 => "es256",
        SigningAlg::Es384 => "es384",
        SigningAlg::Es512 => "es512",
        SigningAlg::Ps256 => "ps256",
        SigningAlg::Ps384 => "ps384",
        SigningAlg::Ps512 => "ps512",
        SigningAlg::Ed25519 => "ed25519",
        #[allow(unreachable_patterns)]
        other => return Err(Error::Unsupported(format!("algorithm {other:?}"))),
    })
}

/// Describes `request` to the host as plain data, under `handle`.
///
/// Fails for a request this wrapper has no description for
/// (`FileBuilderRequest` is `#[non_exhaustive]`), and for a timestamp
/// when no `tsa_url` says where it goes.
fn describe(
    handle: u64,
    request: &FileBuilderRequest,
    tsa_url: Option<&str>,
) -> Result<PendingRequest, Error> {
    Ok(match request {
        FileBuilderRequest::Read { stream, range } => PendingRequest::Read {
            id: handle,
            stream: Stream::from_engine(*stream)?,
            start: range.start,
            len: range.len,
        },
        FileBuilderRequest::Length { stream } => PendingRequest::Length {
            id: handle,
            stream: Stream::from_engine(*stream)?,
        },
        FileBuilderRequest::Write {
            stream,
            offset,
            bytes,
        } => PendingRequest::Write {
            id: handle,
            stream: Stream::from_engine(*stream)?,
            offset: *offset,
            bytes: bytes.clone(),
        },
        FileBuilderRequest::Sign {
            purpose: SignPurpose::Claim,
            alg,
            data,
        } => PendingRequest::Sign {
            id: handle,
            alg: alg_name(*alg)?,
            data: data.clone(),
        },
        // No `BuildSettings` this wrapper accepts names an identity
        // assertion, so none can be asked for; refused rather than
        // answered with the claim's key if one ever were.
        FileBuilderRequest::Sign { purpose, .. } => {
            return Err(Error::Unsupported(format!("signing for {purpose:?}")))
        }
        FileBuilderRequest::Timestamp { digest, hash_alg } => PendingRequest::Timestamp {
            id: handle,
            url: tsa_url
                .ok_or_else(|| Error::Unsupported("a timestamp with no tsa_url".to_string()))?
                .to_string(),
            request: timestamp_request(digest, *hash_alg)
                .map_err(|err| Error::Unsupported(err.to_string()))?,
        },
        other => return Err(Error::Unsupported(format!("{other:?}"))),
    })
}

/// The engine's form of the host's `reply`.
///
/// A timestamp response is unwrapped to its bare token here; one the
/// authority refused, or that is not a `TimeStampResp` at all, becomes a
/// failed reply, which fails the build like any other host failure.
fn engine_reply(reply: Reply) -> Result<FileBuilderReply, Error> {
    Ok(match reply {
        Reply::TimestampResponse(response) => match timestamp_token(&response) {
            Ok(token) => FileBuilderReply::Timestamp(token),
            Err(err) => FileBuilderReply::Failed(err),
        },
        Reply::Bytes(bytes) => FileBuilderReply::Bytes(bytes),
        Reply::Length(len) => FileBuilderReply::Length(len),
        Reply::Written => FileBuilderReply::Written,
        Reply::Signature(bytes) => FileBuilderReply::Signature(bytes),
        Reply::Failed(message) => FileBuilderReply::Failed(HostError::new(message)),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm};
    use contentauth_c2pa_sign_baseline::BASELINE_DEFINITION;

    use super::*;

    fn session() -> NodeBuildSession {
        NodeBuildSession::new(BASELINE_DEFINITION, "image/jpeg", "es256", vec![vec![1]]).unwrap()
    }

    #[test]
    fn every_engine_request_is_described_to_the_host() {
        let range = ByteRange { start: 5, len: 7 };
        let (src, out) = (Engine::SOURCE_STREAM, Engine::OUTPUT_STREAM);

        assert_eq!(
            describe(1, &FileBuilderRequest::Read { stream: src, range }, None).unwrap(),
            PendingRequest::Read {
                id: 1,
                stream: Stream::Source,
                start: 5,
                len: 7
            }
        );
        assert_eq!(
            describe(2, &FileBuilderRequest::Length { stream: out }, None).unwrap(),
            PendingRequest::Length {
                id: 2,
                stream: Stream::Output
            }
        );
        assert_eq!(
            describe(
                3,
                &FileBuilderRequest::Write {
                    stream: out,
                    offset: 9,
                    bytes: vec![1, 2]
                },
                None
            )
            .unwrap(),
            PendingRequest::Write {
                id: 3,
                stream: Stream::Output,
                offset: 9,
                bytes: vec![1, 2]
            }
        );
        assert_eq!(
            describe(
                4,
                &FileBuilderRequest::Sign {
                    purpose: SignPurpose::Claim,
                    alg: SigningAlg::Ps384,
                    data: vec![3]
                },
                None
            )
            .unwrap(),
            PendingRequest::Sign {
                id: 4,
                alg: "ps384",
                data: vec![3]
            }
        );
        assert!(matches!(
            describe(
                5,
                &FileBuilderRequest::Sign {
                    purpose: SignPurpose::Identity {
                        label: "cawg.identity".to_string()
                    },
                    alg: SigningAlg::Es256,
                    data: vec![3]
                },
                None
            ),
            Err(Error::Unsupported(_))
        ));
    }

    fn timestamp_engine_request() -> FileBuilderRequest {
        FileBuilderRequest::Timestamp {
            digest: vec![0xab; 32],
            hash_alg: HashAlgorithm::Sha256,
        }
    }

    #[test]
    fn a_timestamp_request_is_described_with_its_url_and_encoded_request() {
        let pending =
            describe(5, &timestamp_engine_request(), Some("https://tsa.example/")).unwrap();

        let PendingRequest::Timestamp { id, url, request } = pending else {
            panic!("expected a timestamp request");
        };
        assert_eq!(id, 5);
        assert_eq!(url, "https://tsa.example/");
        // A DER SEQUENCE carrying the digest, with certReq set.
        assert_eq!(request[0], 0x30);
        assert!(request.windows(32).any(|w| w == [0xab; 32]));
        assert!(request.ends_with(&[0x01, 0x01, 0xff]));
    }

    #[test]
    fn a_timestamp_request_with_no_tsa_url_is_unsupported() {
        let err = describe(1, &timestamp_engine_request(), None).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn a_timestamp_response_is_unwrapped_to_its_token() {
        // PKIStatusInfo { granted }, then a token SEQUENCE { OID 1.2 }.
        let granted = vec![
            0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x06, 0x01, 0x2a,
        ];
        assert!(matches!(
            engine_reply(Reply::TimestampResponse(granted)).unwrap(),
            FileBuilderReply::Timestamp(token) if token == [0x30, 0x03, 0x06, 0x01, 0x2a]
        ));

        // A refusal, and garbage, both fail the build rather than panic.
        let refused = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        for bad in [refused, vec![1, 2, 3]] {
            assert!(matches!(
                engine_reply(Reply::TimestampResponse(bad)).unwrap(),
                FileBuilderReply::Failed(_)
            ));
        }
    }

    #[test]
    fn a_tsa_url_in_the_definition_makes_the_session_ask_for_a_timestamp() {
        let json = BASELINE_DEFINITION.replace(
            "\"title\"",
            "\"tsa_url\": \"https://tsa.example/\", \"title\"",
        );
        let session = NodeBuildSession::new(&json, "image/jpeg", "es256", vec![vec![1]]).unwrap();
        assert_eq!(session.tsa_url.as_deref(), Some("https://tsa.example/"));

        let bad = BASELINE_DEFINITION.replace("\"title\"", "\"tsa_url\": \"ftp://x/\", \"title\"");
        assert!(matches!(
            NodeBuildSession::new(&bad, "image/jpeg", "es256", vec![]),
            Err(Error::Definition(_))
        ));
    }

    #[test]
    fn replies_map_to_the_engines_kind() {
        assert!(
            matches!(engine_reply(Reply::Bytes(vec![1])).unwrap(), FileBuilderReply::Bytes(b) if b == [1])
        );
        assert!(matches!(
            engine_reply(Reply::Length(3)).unwrap(),
            FileBuilderReply::Length(3)
        ));
        assert!(matches!(
            engine_reply(Reply::Written).unwrap(),
            FileBuilderReply::Written
        ));
        assert!(matches!(
            engine_reply(Reply::Signature(vec![2])).unwrap(),
            FileBuilderReply::Signature(b) if b == [2]
        ));
        assert!(matches!(
            engine_reply(Reply::Failed("no".to_string())).unwrap(),
            FileBuilderReply::Failed(e) if e.message == "no"
        ));
    }

    #[test]
    fn every_algorithm_name_round_trips_and_an_unknown_stream_is_unsupported() {
        for name in [
            "es256", "es384", "es512", "ps256", "ps384", "ps512", "ed25519",
        ] {
            let alg = parse_alg(name).unwrap();
            assert_eq!(alg_name(alg).unwrap(), name);
        }

        assert!(matches!(
            Stream::from_engine(contentauth_c2pa_primitives::StreamId::new(999)),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn arguments_are_checked_before_any_request() {
        let new = |json: &str, format: &str, alg: &str| {
            NodeBuildSession::new(json, format, alg, vec![])
                .err()
                .unwrap()
        };
        assert!(matches!(
            new(BASELINE_DEFINITION, "image/png", "es256"),
            Error::C2pa(C2paError::UnsupportedType)
        ));
        assert!(matches!(
            new(BASELINE_DEFINITION, "jpg", "rot13"),
            Error::C2pa(C2paError::BadParam(_))
        ));
        assert!(matches!(new("{", "jpg", "ES256"), Error::Definition(_)));
    }

    #[test]
    fn a_fresh_session_asks_for_the_source_length_and_forgets_answered_requests() {
        let mut session = session();
        let Step::Pending(requests) = session.advance().unwrap() else {
            panic!("a fresh session needs the host");
        };
        assert!(!requests.is_empty());
        assert_eq!(session.reported.len(), requests.len());
        assert_eq!(session.handles.len(), requests.len());

        // Reported once only.
        let Step::Pending(again) = session.advance().unwrap() else {
            panic!("still waiting");
        };
        assert!(again.is_empty());

        session
            .fulfill(requests[0].id(), Reply::Failed("no".to_string()))
            .unwrap();
        assert_eq!(session.reported.len(), requests.len() - 1);
        assert_eq!(session.handles.len(), requests.len() - 1);

        // Answered twice, or never issued, is refused.
        assert!(session.fulfill(requests[0].id(), Reply::Written).is_err());
        assert!(session.fulfill(9999, Reply::Written).is_err());
    }

    #[test]
    fn a_failed_reply_fails_the_build() {
        let mut session = session();
        let Step::Pending(requests) = session.advance().unwrap() else {
            panic!("needs host");
        };
        for request in &requests {
            session
                .fulfill(request.id(), Reply::Failed("disk on fire".to_string()))
                .unwrap();
        }
        let err = session.advance().unwrap_err();
        assert!(err.to_string().contains("disk on fire"), "{err}");
    }

    #[test]
    fn every_pending_request_reports_its_own_handle() {
        let s = Stream::Source;
        let requests = [
            PendingRequest::Read {
                id: 7,
                stream: s,
                start: 0,
                len: 0,
            },
            PendingRequest::Length { id: 8, stream: s },
            PendingRequest::Write {
                id: 9,
                stream: s,
                offset: 0,
                bytes: vec![],
            },
            PendingRequest::Sign {
                id: 10,
                alg: "es256",
                data: vec![],
            },
            PendingRequest::Timestamp {
                id: 11,
                url: String::new(),
                request: vec![],
            },
        ];
        let ids: Vec<u64> = requests.iter().map(PendingRequest::id).collect();
        assert_eq!(ids, [7, 8, 9, 10, 11]);
        assert_eq!(Stream::Source.as_str(), "source");
        assert_eq!(Stream::Output.as_str(), "output");
    }
}
