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

//! A synchronous [`FileReadSession`] host that services the session's
//! outstanding requests concurrently.
//!
//! [`crate::read_manifest`] answers requests one at a time, which wastes
//! the one thing the session offers a host that pays a round trip per read
//! (a network-backed or slow store): while hashing the asset, it keeps
//! several chunk requests outstanding at once (see
//! [`ReadSettings::hash_chunk_size`]) and will fold them in whatever order
//! they arrive. This host puts a pool of worker threads behind those
//! requests.
//!
//! # How the loop differs from the sequential host's
//!
//! The sequential host answers a whole batch, then calls `advance`. Here
//! `advance` is called as soon as *any* reply has arrived, so the session
//! can fold what it has and issue the next chunk while slower ones are
//! still in flight — a sliding window rather than a batch with a barrier
//! after every round, which would leave every worker idle waiting for the
//! slowest read of the round.
//!
//! The session itself still runs on the calling thread only; the workers
//! do nothing but answer requests, so no part of the session is shared or
//! locked.
//!
//! # What this needs from the source
//!
//! The sequential host's `Read + Seek` is one cursor, which concurrent
//! reads would fight over. [`RangeSource`] is the same idea without the
//! cursor: every read names its own offset, so any number may be in
//! progress at once.

use std::{
    collections::HashSet,
    io,
    num::NonZeroUsize,
    sync::{mpsc, Mutex},
    thread,
};

use contentauth_c2pa_format::FormatHandler;
use contentauth_c2pa_primitives::ByteRange;
use contentauth_c2pa_reader::{ReadReport, ReadSettings};
use contentauth_state_machine::{RequestId, Session, Step};

use crate::{
    drive,
    error::Error,
    session::{FileReadReply, FileReadRequest, FileReadSession},
};

/// An asset that can serve any number of byte-range reads at once.
///
/// What a network object store, an HTTP server honoring `Range`, or a file
/// read with `pread` all are: no position is shared between reads, so
/// `&self` suffices and reads on different threads do not interfere.
pub trait RangeSource: Sync {
    /// The asset's total length in bytes.
    fn length(&self) -> io::Result<u64>;

    /// Exactly the bytes at `range`; a range extending past the end of the
    /// asset is an error rather than a short read, since a short read would
    /// shift everything hashed after it.
    fn read_range(&self, range: ByteRange) -> io::Result<Vec<u8>>;
}

impl RangeSource for [u8] {
    fn length(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }

    fn read_range(&self, range: ByteRange) -> io::Result<Vec<u8>> {
        let slice = usize::try_from(range.start)
            .ok()
            .zip(usize::try_from(range.len).ok())
            .and_then(|(start, len)| self.get(start..start.checked_add(len)?));

        slice.map(<[u8]>::to_vec).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "range extends past the end of the asset",
            )
        })
    }
}

#[cfg(unix)]
impl RangeSource for std::fs::File {
    fn length(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn read_range(&self, range: ByteRange) -> io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;

        let len = usize::try_from(range.len)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let mut buf = vec![0u8; len];
        self.read_exact_at(&mut buf, range.start)?;
        Ok(buf)
    }
}

/// Locates and reads the C2PA manifest store embedded in `source`,
/// validating it per `settings`, with up to `workers` requests answered at
/// once.
///
/// Reads exactly what [`crate::read_manifest`] would, and produces the same
/// report; only the pace differs. Every request, not just the asset reads,
/// goes to a worker — the current time is the wall clock's and OCSP is
/// answered as failed, as in the sequential host.
///
/// More workers than the session ever has outstanding at once do nothing:
/// while hashing, that is eight chunk requests (see
/// [`ReadSettings::hash_chunk_size`], which sets how large each is).
/// `workers` of one is a valid, if pointless, configuration that behaves
/// like the sequential host with a thread's overhead.
///
/// # Errors
///
/// As [`crate::read_manifest`], and [`Error::ConcurrentHost`] if a worker
/// thread cannot be started.
pub fn read_manifest_concurrent<H, S>(
    handler: &H,
    source: &S,
    settings: ReadSettings,
    workers: NonZeroUsize,
) -> Result<ReadReport, Error>
where
    H: FormatHandler,
    S: RangeSource + ?Sized,
{
    let (job_tx, job_rx) = mpsc::channel::<(RequestId, FileReadRequest)>();
    let job_rx = Mutex::new(job_rx);
    let job_rx = &job_rx;
    let (done_tx, done_rx) = mpsc::channel::<(RequestId, FileReadReply)>();

    // `move`: `job_tx` must be dropped when this closure returns, however
    // it returns, so the workers see their queue close and the scope can
    // join them.
    thread::scope(move |scope| {
        for index in 0..workers.get() {
            let done_tx = done_tx.clone();

            thread::Builder::new()
                .name(format!("c2pa-read-{index}"))
                .spawn_scoped(scope, move || loop {
                    // The lock is held only while waiting for a job, never
                    // while answering one.
                    let job = match job_rx.lock() {
                        Ok(queue) => queue.recv(),
                        Err(_) => return,
                    };
                    let Ok((id, request)) = job else { return };

                    if done_tx.send((id, answer(source, &request))).is_err() {
                        return;
                    }
                })
                .map_err(|err| {
                    Error::ConcurrentHost(format!("could not start a worker thread: {err}"))
                })?;
        }

        // Only the workers' clones remain, so if they all stop, `recv`
        // below fails instead of waiting forever.
        drop(done_tx);

        let mut session = FileReadSession::new(handler, settings);
        let mut dispatched: HashSet<RequestId> = HashSet::new();

        loop {
            if session.advance()? == Step::Complete {
                return session.finish();
            }

            for request in session.outstanding_requests() {
                if dispatched.insert(request.id)
                    && job_tx.send((request.id, request.kind.clone())).is_err()
                {
                    return Err(Error::ConcurrentHost(
                        "every worker thread stopped".to_string(),
                    ));
                }
            }

            if dispatched.is_empty() {
                return Err(Error::ConcurrentHost(
                    "the session is waiting on the host with no request outstanding".to_string(),
                ));
            }

            // Block for one reply, then take whatever else has already
            // arrived, so one `advance` sees as much progress as possible.
            let first = done_rx
                .recv()
                .map_err(|_| Error::ConcurrentHost("every worker thread stopped".to_string()))?;

            for (id, reply) in std::iter::once(first).chain(done_rx.try_iter()) {
                dispatched.remove(&id);
                session.fulfill(id, reply)?;
            }
        }
    })
}

fn answer<S: RangeSource + ?Sized>(source: &S, request: &FileReadRequest) -> FileReadReply {
    match request {
        FileReadRequest::Read { range, .. } => match source.read_range(*range) {
            Ok(bytes) => FileReadReply::Bytes(bytes),
            Err(err) => FileReadReply::Failed(drive::read_failed(*range, &err)),
        },

        FileReadRequest::Length { .. } => match source.length() {
            Ok(len) => FileReadReply::Length(len),
            Err(err) => FileReadReply::Failed(drive::length_failed(&err)),
        },

        FileReadRequest::CurrentDateTime => FileReadReply::CurrentDateTime(drive::now_unix()),

        FileReadRequest::Ocsp { .. } => FileReadReply::Failed(drive::ocsp_unavailable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, len: u64) -> ByteRange {
        ByteRange { start, len }
    }

    #[test]
    fn a_slice_serves_ranges_and_its_length() {
        let bytes: &[u8] = &[10, 11, 12, 13, 14];

        assert_eq!(bytes.length().ok(), Some(5));
        assert_eq!(bytes.read_range(range(1, 3)).ok(), Some(vec![11, 12, 13]));
        assert_eq!(bytes.read_range(range(5, 0)).ok(), Some(vec![]));
    }

    #[test]
    fn a_slice_refuses_a_range_past_its_end_rather_than_reading_short() {
        let bytes: &[u8] = &[1, 2, 3];

        for bad in [
            range(0, 4),
            range(3, 1),
            range(u64::MAX, 1),
            range(1, u64::MAX),
        ] {
            let kind = bytes.read_range(bad).err().map(|err| err.kind());
            assert_eq!(kind, Some(io::ErrorKind::UnexpectedEof), "{bad:?}");
        }
    }
}
