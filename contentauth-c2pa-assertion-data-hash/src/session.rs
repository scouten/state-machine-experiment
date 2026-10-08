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

//! [`DataHashSession`]: hash an asset, host-streamed, into a `c2pa.hash.data`
//! assertion.

use std::collections::HashMap;

use contentauth_c2pa_primitives::{
    hash::Hasher, ByteRange, EncodedAssertion, HashAlgorithm, HostError, StreamId,
};
use contentauth_state_machine::{
    HostRequest, ProtocolError, Request, RequestId, Session, SessionCore, Step,
};

use crate::DataHash;

/// Bytes requested per chunk.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Maximum chunks in play (outstanding or buffered) at once, bounding peak
/// memory at `WINDOW × CHUNK_SIZE` however large the asset is.
const WINDOW: usize = 8;

/// What a [`DataHashSession`] may ask its host for.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DataHashRequest {
    /// The total length of the asset stream. Reply with
    /// [`DataHashReply::AssetLength`].
    AssetLength {
        /// The stream to measure.
        stream: StreamId,
    },

    /// A range of the asset stream. Reply with [`DataHashReply::AssetBytes`],
    /// carrying exactly `range.len` bytes.
    AssetBytes {
        /// The stream to read.
        stream: StreamId,

        /// The range wanted.
        range: ByteRange,
    },
}

/// The host's answer to a [`DataHashRequest`].
#[derive(Debug)]
#[non_exhaustive]
pub enum DataHashReply {
    /// Answers [`DataHashRequest::AssetLength`].
    AssetLength(u64),

    /// Answers [`DataHashRequest::AssetBytes`].
    AssetBytes(Vec<u8>),

    /// The host could not do it. Valid for any request.
    Failed(HostError),
}

impl Request for DataHashRequest {
    type Reply = DataHashReply;

    fn expected_reply(&self) -> &'static str {
        match self {
            Self::AssetLength { .. } => "AssetLength",
            Self::AssetBytes { .. } => "AssetBytes",
        }
    }

    fn accepts(&self, reply: &DataHashReply) -> bool {
        matches!(
            (self, reply),
            (_, DataHashReply::Failed(_))
                | (Self::AssetLength { .. }, DataHashReply::AssetLength(_))
                | (Self::AssetBytes { .. }, DataHashReply::AssetBytes(_))
        )
    }
}

/// Why a data hash could not be computed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A violation of the session interaction contract.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// The host could not read the asset.
    #[error("the host failed: {0}")]
    Host(#[from] HostError),

    /// The configured exclusions are unordered, overlapping, or run past
    /// the end of the asset.
    #[error("invalid exclusions: {0}")]
    InvalidExclusions(&'static str),

    /// A read returned a different number of bytes than were asked for.
    #[error("the host returned {actual} bytes for a {expected}-byte read")]
    ShortRead {
        /// Bytes requested.
        expected: u64,
        /// Bytes returned.
        actual: usize,
    },

    /// The CBOR encoder failed.
    #[error(transparent)]
    Cbor(#[from] c2pa_cbor::Error),
}

/// What to hash, and how.
#[derive(Clone, Debug)]
pub struct DataHashSettings {
    /// The asset stream.
    pub stream: StreamId,

    /// The digest algorithm.
    pub alg: HashAlgorithm,

    /// Ranges to leave out, ascending and non-overlapping. Empty for a
    /// sidecar manifest.
    pub exclusions: Vec<ByteRange>,

    /// Recorded as the assertion's `name`, if set.
    pub name: Option<String>,
}

impl DataHashSettings {
    /// Hashes the whole of `stream` under `alg`.
    pub fn whole_asset(stream: StreamId, alg: HashAlgorithm) -> Self {
        Self {
            stream,
            alg,
            exclusions: Vec::new(),
            name: None,
        }
    }
}

#[derive(Debug)]
enum State {
    Start,
    AwaitingLength(RequestId),
    Hashing(Box<Chunks>),
    Done(Box<EncodedAssertion>),
    Poisoned,
}

/// Hashes a stream, in bounded memory, into a `c2pa.hash.data` assertion.
/// See the crate documentation.
#[derive(Debug)]
pub struct DataHashSession {
    settings: DataHashSettings,
    core: SessionCore<DataHashRequest>,
    state: State,
}

impl DataHashSession {
    /// Prepares to hash.
    pub fn new(settings: DataHashSettings) -> Self {
        Self {
            settings,
            core: SessionCore::default(),
            state: State::Start,
        }
    }

    fn step(&mut self) -> Result<Option<Step>, Error> {
        match std::mem::replace(&mut self.state, State::Poisoned) {
            State::Start => {
                let id = self.core.issue(DataHashRequest::AssetLength {
                    stream: self.settings.stream,
                });
                self.state = State::AwaitingLength(id);
                Ok(Some(Step::AwaitHost))
            }

            State::AwaitingLength(id) => match self.core.take_reply(id) {
                None => {
                    self.state = State::AwaitingLength(id);
                    Ok(Some(Step::AwaitHost))
                }
                Some(DataHashReply::AssetLength(len)) => {
                    let ranges = included_ranges(len, &self.settings.exclusions)?;
                    self.state = State::Hashing(Box::new(Chunks::new(self.settings.alg, &ranges)));
                    Ok(None)
                }
                Some(DataHashReply::Failed(e)) => Err(e.into()),
                Some(_) => Err(ProtocolError::SessionFailed.into()),
            },

            State::Hashing(mut chunks) => {
                chunks.issue(&mut self.core, self.settings.stream);
                chunks.absorb(&mut self.core)?;
                if chunks.is_finished() {
                    let digest = chunks.finish();
                    let mut dh = DataHash::new(self.settings.alg, digest)
                        .with_exclusions(self.settings.exclusions.clone());
                    if let Some(name) = &self.settings.name {
                        dh = dh.with_name(name.clone());
                    }
                    self.state = State::Done(Box::new(dh.encode()?));
                    self.core.mark_complete();
                    Ok(Some(Step::Complete))
                } else {
                    // Either more chunks to request next time round, or
                    // all in flight.
                    chunks.issue(&mut self.core, self.settings.stream);
                    self.state = State::Hashing(chunks);
                    Ok(Some(Step::AwaitHost))
                }
            }

            State::Done(a) => {
                self.state = State::Done(a);
                Ok(Some(Step::Complete))
            }

            State::Poisoned => Err(ProtocolError::SessionFailed.into()),
        }
    }
}

impl Session for DataHashSession {
    type Error = Error;
    type Output = EncodedAssertion;
    type Request = DataHashRequest;

    fn advance(&mut self) -> Result<Step, Error> {
        loop {
            match self.step() {
                Ok(Some(step)) => return Ok(step),
                Ok(None) => {}
                Err(e) => {
                    self.core.mark_failed();
                    return Err(e);
                }
            }
        }
    }

    fn outstanding_requests(&self) -> &[HostRequest<DataHashRequest>] {
        self.core.outstanding_requests()
    }

    fn fulfill(&mut self, id: RequestId, reply: DataHashReply) -> Result<(), Error> {
        Ok(self.core.fulfill(id, reply)?)
    }

    fn finish(self) -> Result<EncodedAssertion, Error> {
        self.core.finish_check()?;
        match self.state {
            State::Done(a) => Ok(*a),
            _ => Err(ProtocolError::SessionNotComplete.into()),
        }
    }
}

/// The complement of `exclusions` within `[0, len)`.
fn included_ranges(len: u64, exclusions: &[ByteRange]) -> Result<Vec<ByteRange>, Error> {
    let mut out = Vec::new();
    let mut cursor = 0u64;
    for r in exclusions {
        let end = r
            .start
            .checked_add(r.len)
            .ok_or(Error::InvalidExclusions("range end overflows"))?;
        if r.start < cursor {
            return Err(Error::InvalidExclusions("ranges are unordered or overlap"));
        }
        if end > len {
            return Err(Error::InvalidExclusions(
                "range runs past the end of the asset",
            ));
        }
        if r.start > cursor {
            out.push(ByteRange {
                start: cursor,
                len: r.start - cursor,
            });
        }
        cursor = end;
    }
    if cursor < len {
        out.push(ByteRange {
            start: cursor,
            len: len - cursor,
        });
    }
    Ok(out)
}

/// Windowed, order-restoring chunk hashing.
#[derive(Debug)]
struct Chunks {
    hasher: Hasher,
    chunks: Vec<ByteRange>,
    next_to_issue: usize,
    next_to_fold: usize,
    outstanding: Vec<(RequestId, usize)>,
    buffered: HashMap<usize, Vec<u8>>,
}

impl Chunks {
    fn new(alg: HashAlgorithm, ranges: &[ByteRange]) -> Self {
        let mut chunks = Vec::new();
        for range in ranges {
            let mut offset = range.start;
            let end = range.start + range.len;
            while offset < end {
                let len = CHUNK_SIZE.min(end - offset);
                chunks.push(ByteRange { start: offset, len });
                offset += len;
            }
        }
        Self {
            hasher: Hasher::new(alg),
            chunks,
            next_to_issue: 0,
            next_to_fold: 0,
            outstanding: Vec::new(),
            buffered: HashMap::new(),
        }
    }

    fn issue(&mut self, core: &mut SessionCore<DataHashRequest>, stream: StreamId) {
        while self.next_to_issue < self.chunks.len()
            && self.next_to_issue - self.next_to_fold < WINDOW
        {
            let index = self.next_to_issue;
            let id = core.issue(DataHashRequest::AssetBytes {
                stream,
                range: self.chunks[index],
            });
            self.outstanding.push((id, index));
            self.next_to_issue += 1;
        }
    }

    fn absorb(&mut self, core: &mut SessionCore<DataHashRequest>) -> Result<(), Error> {
        let mut i = 0;
        while i < self.outstanding.len() {
            let (id, index) = self.outstanding[i];
            match core.take_reply(id) {
                None => i += 1,
                Some(DataHashReply::AssetBytes(bytes)) => {
                    let expected = self.chunks[index].len;
                    if bytes.len() as u64 != expected {
                        return Err(Error::ShortRead {
                            expected,
                            actual: bytes.len(),
                        });
                    }
                    self.buffered.insert(index, bytes);
                    self.outstanding.swap_remove(i);
                }
                Some(DataHashReply::Failed(e)) => return Err(e.into()),
                Some(_) => return Err(ProtocolError::SessionFailed.into()),
            }
        }
        while let Some(bytes) = self.buffered.remove(&self.next_to_fold) {
            self.hasher.update(&bytes);
            self.next_to_fold += 1;
        }
        Ok(())
    }

    fn is_finished(&self) -> bool {
        self.next_to_fold == self.chunks.len()
    }

    fn finish(self) -> Vec<u8> {
        self.hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use c2pa_cbor::Value;

    use super::*;

    /// Drives a session over `asset`, answering requests in reverse order
    /// to show order does not matter.
    fn run(asset: &[u8], settings: DataHashSettings) -> Result<EncodedAssertion, Error> {
        let mut s = DataHashSession::new(settings);
        loop {
            if s.advance()? == Step::Complete {
                return s.finish();
            }
            let pending: Vec<_> = s
                .outstanding_requests()
                .iter()
                .map(|r| (r.id, r.kind.clone()))
                .collect();
            for (id, req) in pending.into_iter().rev() {
                let reply = match req {
                    DataHashRequest::AssetLength { .. } => {
                        DataHashReply::AssetLength(asset.len() as u64)
                    }
                    DataHashRequest::AssetBytes { range, .. } => DataHashReply::AssetBytes(
                        asset[range.start as usize..(range.start + range.len) as usize].to_vec(),
                    ),
                };
                s.fulfill(id, reply)?;
            }
        }
    }

    fn digest_of(a: &EncodedAssertion) -> Vec<u8> {
        let v: Value = c2pa_cbor::from_slice(&a.cbor).unwrap();
        match v.as_map().unwrap().get(&Value::Text("hash".into())) {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("no hash: {other:?}"),
        }
    }

    #[test]
    fn hashes_a_multi_chunk_asset_in_order() {
        let asset: Vec<u8> = (0..(CHUNK_SIZE * 20 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let a = run(
            &asset,
            DataHashSettings::whole_asset(StreamId::new(0), HashAlgorithm::Sha256),
        )
        .unwrap();
        assert_eq!(a.label, "c2pa.hash.data");
        assert_eq!(digest_of(&a), HashAlgorithm::Sha256.digest(&asset));
    }

    #[test]
    fn skips_exclusions() {
        let asset: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut settings = DataHashSettings::whole_asset(StreamId::new(0), HashAlgorithm::Sha384);
        settings.exclusions = vec![
            ByteRange { start: 10, len: 20 },
            ByteRange { start: 500, len: 5 },
        ];
        let a = run(&asset, settings).unwrap();

        let mut expected = asset[..10].to_vec();
        expected.extend_from_slice(&asset[30..500]);
        expected.extend_from_slice(&asset[505..]);
        assert_eq!(digest_of(&a), HashAlgorithm::Sha384.digest(&expected));
    }

    #[test]
    fn an_empty_asset_hashes_to_the_empty_digest() {
        let a = run(
            &[],
            DataHashSettings::whole_asset(StreamId::new(0), HashAlgorithm::Sha256),
        )
        .unwrap();
        assert_eq!(digest_of(&a), HashAlgorithm::Sha256.digest(&[]));
    }

    #[test]
    fn bad_exclusions_are_errors() {
        for ex in [
            vec![
                ByteRange { start: 5, len: 10 },
                ByteRange { start: 8, len: 1 },
            ],
            vec![ByteRange { start: 90, len: 20 }],
            vec![ByteRange {
                start: u64::MAX,
                len: 2,
            }],
        ] {
            let mut settings =
                DataHashSettings::whole_asset(StreamId::new(0), HashAlgorithm::Sha256);
            settings.exclusions = ex;
            assert!(matches!(
                run(&[0; 100], settings),
                Err(Error::InvalidExclusions(_))
            ));
        }
    }

    #[test]
    fn a_failing_host_fails_the_session() {
        let mut s = DataHashSession::new(DataHashSettings::whole_asset(
            StreamId::new(0),
            HashAlgorithm::Sha256,
        ));
        assert_eq!(s.advance().unwrap(), Step::AwaitHost);
        let id = s.outstanding_requests()[0].id;
        s.fulfill(id, DataHashReply::Failed(HostError::new("gone")))
            .unwrap();
        assert!(matches!(s.advance(), Err(Error::Host(_))));
    }
}
