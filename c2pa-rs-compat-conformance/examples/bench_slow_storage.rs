//! Benchmark: reading and validating a signed JPEG from slow, high-latency
//! storage, with the real `c2pa` crate against this workspace's reader
//! driven sequentially and concurrently.
//!
//! ```sh
//! cargo run --release --example bench_slow_storage
//! cargo run --release --example bench_slow_storage -- \
//!     --size-mib 64 --latency-ms 40 --mib-per-sec 25 --block-kib 512 --runs 5
//! ```
//!
//! # What is simulated
//!
//! The asset lives in memory behind a [`Store`] that behaves like an
//! object store or HTTP server honoring `Range`: every request costs a
//! fixed latency plus the transfer time of its bytes at a per-connection
//! bandwidth, and any number may be in flight at once (each on its own
//! connection, so each pays latency and bandwidth independently). Nothing
//! here touches a network; `thread::sleep` stands in for the wire, which
//! makes the run repeatable and independent of the machine's disk.
//!
//! # How each reader reaches it
//!
//! * **c2pa-rs** and the **sequential** state-machine host want a `Read +
//!   Seek`. [`SimStream`] is the realistic one: it fetches whole
//!   `--block-kib` blocks and keeps the last, as a range-reading stream
//!   with readahead would. Without that, c2pa-rs's JPEG parser alone would
//!   make thousands of tiny reads and the comparison would measure the
//!   absence of a buffer, not the reader. Both go through the same stream
//!   type, so they pay the same price for the same bytes.
//! * The **concurrent** host gets the store itself as a `RangeSource`: each
//!   chunk the session asks for is one request, the way a host that knows
//!   it is talking to a ranged store would issue it.
//!
//! # What the numbers say, and do not
//!
//! The gain comes from overlapping *waiting*: with latency or per-connection
//! bandwidth limits, eight requests in flight finish in about the time of
//! one. On a fast local disk there is nothing to overlap, and the extra
//! threads are overhead — run with `--latency-ms 0 --mib-per-sec 0` to see
//! that. The sans-I/O session is the same code in every state-machine row;
//! only the host differs. The window of eight outstanding chunk requests is
//! the engine's, so workers beyond eight add nothing.

use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    num::NonZeroUsize,
    process::ExitCode,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use contentauth_c2pa_file_builder::{build_and_sign, HostError, SigningAlg};
use contentauth_c2pa_file_reader::{
    read_manifest, read_manifest_concurrent, ByteRange, ChunkSize, HashWindow, RangeSource,
    ReadSettings,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_sign_baseline::{
    fixtures::{SOURCE_JPEG, TEST_SIGNER_CERT, TEST_SIGNER_KEY_PEM},
    Definition, BASELINE_DEFINITION,
};

/// Latency, bandwidth and counters of one simulated store.
struct Store {
    bytes: Vec<u8>,
    latency: Duration,

    /// Bytes per second on each connection; `None` for unlimited.
    bytes_per_sec: Option<f64>,

    requests: AtomicUsize,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

impl Store {
    fn new(bytes: Vec<u8>, latency: Duration, bytes_per_sec: Option<f64>) -> Self {
        Self {
            bytes,
            latency,
            bytes_per_sec,
            requests: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn reset(&self) {
        self.requests.store(0, Ordering::SeqCst);
        self.peak.store(0, Ordering::SeqCst);
    }

    /// One request: pays latency plus transfer time, then returns the bytes.
    fn fetch(&self, start: u64, len: u64) -> io::Result<Vec<u8>> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.requests.fetch_add(1, Ordering::SeqCst);

        let transfer = self.bytes_per_sec.map_or(Duration::ZERO, |rate| {
            Duration::from_secs_f64(len as f64 / rate)
        });
        thread::sleep(self.latency + transfer);

        let end = start.checked_add(len);
        let slice = usize::try_from(start)
            .ok()
            .zip(end.and_then(|end| usize::try_from(end).ok()))
            .and_then(|(start, end)| self.bytes.get(start..end));

        self.in_flight.fetch_sub(1, Ordering::SeqCst);

        slice
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "range past end of asset"))
    }
}

impl RangeSource for Store {
    fn length(&self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }

    fn read_range(&self, range: ByteRange) -> io::Result<Vec<u8>> {
        self.fetch(range.start, range.len)
    }
}

/// Reads smaller than this come from the serial parse phase (segment
/// headers), not the hash phase; [`BufferedRangeSource`] serves them from a
/// cached block. Any hash chunk the engine issues is far larger (64 KiB and
/// up), so it bypasses the cache and still overlaps with its peers.
const SMALL_READ_MAX: u64 = 16 * 1024;

/// A [`RangeSource`] that gives the serial `locate` phase the same block
/// readahead [`SimStream`] gives the sequential readers, so the concurrent
/// host is not penalized for parsing a JPEG one tiny range request at a
/// time. Large reads (the hash chunks) pass straight through, uncached and
/// concurrent, since caching them would only serialize the overlap this
/// host exists to exploit.
struct BufferedRangeSource {
    inner: Arc<Store>,
    block: u64,
    cached: Mutex<Option<(u64, Vec<u8>)>>,
}

impl BufferedRangeSource {
    fn new(inner: Arc<Store>, block: u64) -> Self {
        Self {
            inner,
            block,
            cached: Mutex::new(None),
        }
    }
}

impl RangeSource for BufferedRangeSource {
    fn length(&self) -> io::Result<u64> {
        self.inner.length()
    }

    fn read_range(&self, range: ByteRange) -> io::Result<Vec<u8>> {
        if range.len > SMALL_READ_MAX {
            return self.inner.read_range(range);
        }

        let len = self.inner.bytes.len() as u64;
        let block_start = range.start - range.start % self.block;
        let block_len = self.block.min(len - block_start);

        let mut cached = self
            .cached
            .lock()
            .map_err(|_| io::Error::other("readahead cache poisoned"))?;
        let hit = matches!(&*cached, Some((start, _)) if *start == block_start);
        if !hit {
            *cached = Some((block_start, self.inner.fetch(block_start, block_len)?));
        }

        let (start, block) = cached.as_ref().expect("just populated");
        let offset = (range.start - start) as usize;
        let end = offset + range.len as usize;
        block
            .get(offset..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "range past end of asset"))
    }
}

/// A `Read + Seek` over a [`Store`] that fetches whole aligned blocks and
/// keeps the most recent one.
struct SimStream {
    store: Arc<Store>,
    pos: u64,
    block: u64,
    cached: Option<(u64, Vec<u8>)>,
}

impl SimStream {
    fn new(store: Arc<Store>, block: u64) -> Self {
        Self {
            store,
            pos: 0,
            block,
            cached: None,
        }
    }
}

impl Read for SimStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.store.bytes.len() as u64;
        if self.pos >= len || buf.is_empty() {
            return Ok(0);
        }

        let block_start = self.pos - self.pos % self.block;
        let hit = matches!(&self.cached, Some((start, _)) if *start == block_start);
        if !hit {
            let block_len = self.block.min(len - block_start);
            self.cached = Some((block_start, self.store.fetch(block_start, block_len)?));
        }

        let Some((start, block)) = &self.cached else {
            return Ok(0);
        };
        let offset = (self.pos - start) as usize;
        let n = buf.len().min(block.len() - offset);
        buf[..n].copy_from_slice(&block[offset..offset + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SimStream {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let len = self.store.bytes.len() as i64;
        let target = match from {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => len + offset,
            SeekFrom::Current(offset) => self.pos as i64 + offset,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

struct Options {
    size_mib: usize,
    latency_ms: u64,
    mib_per_sec: f64,
    block_kib: u64,
    runs: usize,
    max_workers: usize,
}

impl Options {
    fn parse() -> Result<Self, String> {
        let mut options = Self {
            size_mib: 32,
            latency_ms: 20,
            mib_per_sec: 50.0,
            block_kib: 1024,
            runs: 3,
            max_workers: 8,
        };

        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            let number = || format!("{flag}: not a valid number: {value}");

            match flag.as_str() {
                "--size-mib" => options.size_mib = value.parse().map_err(|_| number())?,
                "--latency-ms" => options.latency_ms = value.parse().map_err(|_| number())?,
                "--mib-per-sec" => options.mib_per_sec = value.parse().map_err(|_| number())?,
                "--block-kib" => options.block_kib = value.parse().map_err(|_| number())?,
                "--runs" => options.runs = value.parse().map_err(|_| number())?,
                "--max-workers" => options.max_workers = value.parse().map_err(|_| number())?,
                other => return Err(format!("unknown option {other}")),
            }
        }

        if options.size_mib == 0 || options.block_kib == 0 || options.runs == 0 {
            return Err("--size-mib, --block-kib and --runs must be at least 1".to_string());
        }
        if options.max_workers == 0 {
            return Err("--max-workers must be at least 1".to_string());
        }
        Ok(options)
    }
}

/// A source JPEG padded to roughly `size` bytes with comment segments, so
/// there is a large asset to hash without changing what is signed.
fn padded_jpeg(size: usize) -> Vec<u8> {
    const MAX_COMMENT: usize = 65_533;

    let mut out = SOURCE_JPEG[..2].to_vec(); // SOI
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    while out.len() + SOURCE_JPEG.len() < size {
        out.extend_from_slice(&[0xff, 0xfe]);
        out.extend_from_slice(&((MAX_COMMENT + 2) as u16).to_be_bytes());
        for _ in 0..MAX_COMMENT {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            out.push(seed as u8);
        }
    }
    out.extend_from_slice(&SOURCE_JPEG[2..]);
    out
}

/// Signs [`padded_jpeg`] with this workspace's builder.
///
/// Uses the baseline crate's conformant definition — a `c2pa.actions.v2`
/// assertion with a `c2pa.created` action — so c2pa-rs, which requires the
/// first action to be `created`/`opened`, validates the result rather than
/// rejecting it as malformed.
fn signed_asset(size: usize) -> Result<Vec<u8>, String> {
    let settings = Definition::from_json(BASELINE_DEFINITION)
        .and_then(|definition| {
            definition.into_settings(SigningAlg::Es256, vec![TEST_SIGNER_CERT.to_vec()])
        })
        .map_err(|err| err.to_string())?;

    let mut output = Cursor::new(Vec::new());
    build_and_sign(
        JpegFormat,
        Cursor::new(padded_jpeg(size)),
        &mut output,
        settings,
        |_alg, data| {
            let signer = c2pa_raw_crypto::signer_from_private_key(
                TEST_SIGNER_KEY_PEM,
                c2pa_raw_crypto::SigningAlg::Es256,
            )
            .map_err(|err| HostError::new(err.to_string()))?;
            signer
                .sign(data)
                .map_err(|err| HostError::new(err.to_string()))
        },
        None,
        None,
    )
    .map_err(|err| err.to_string())?;

    Ok(output.into_inner())
}

struct Outcome {
    elapsed: Duration,
    requests: usize,
    peak: usize,
    state: String,
}

fn timed(store: &Store, work: impl FnOnce() -> Result<String, String>) -> Result<Outcome, String> {
    store.reset();
    let started = Instant::now();
    let state = work()?;
    Ok(Outcome {
        elapsed: started.elapsed(),
        requests: store.requests.load(Ordering::SeqCst),
        peak: store.peak.load(Ordering::SeqCst),
        state,
    })
}

fn c2pa_rs(store: &Arc<Store>, block: u64) -> Result<String, String> {
    let stream = SimStream::new(Arc::clone(store), block);
    let reader = c2pa::Reader::from_context(c2pa::Context::new())
        .with_stream("image/jpeg", stream)
        .map_err(|err| err.to_string())?;

    Ok(match reader.validation_state() {
        c2pa::ValidationState::Trusted => "Trusted",
        c2pa::ValidationState::Valid => "Valid",
        c2pa::ValidationState::Invalid => "Invalid",
    }
    .to_string())
}

fn state_machine_sequential(
    store: &Arc<Store>,
    block: u64,
    settings: ReadSettings,
) -> Result<String, String> {
    let stream = SimStream::new(Arc::clone(store), block);
    let report = read_manifest(&JpegFormat, stream, settings).map_err(|err| err.to_string())?;
    Ok(format!("{:?}", report.validation_state))
}

fn state_machine_concurrent(
    store: &Arc<Store>,
    workers: usize,
    settings: ReadSettings,
    readahead: Option<u64>,
) -> Result<String, String> {
    let workers = NonZeroUsize::new(workers).ok_or("workers must be at least 1")?;
    let report = match readahead {
        Some(block) => {
            let source = BufferedRangeSource::new(Arc::clone(store), block);
            read_manifest_concurrent(&JpegFormat, &source, settings, workers)
        }
        None => read_manifest_concurrent(&JpegFormat, &**store, settings, workers),
    }
    .map_err(|err| err.to_string())?;
    Ok(format!("{:?}", report.validation_state))
}

fn median(runs: &mut [Outcome]) -> &Outcome {
    runs.sort_by_key(|run| run.elapsed);
    &runs[runs.len() / 2]
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// What one benchmark row runs.
enum Scenario {
    C2paRs,
    Sequential,
    Concurrent {
        workers: usize,
        chunk: ChunkSize,
        readahead: Option<u64>,
        window: HashWindow,
    },
}

impl Scenario {
    fn label(&self) -> String {
        match self {
            Self::C2paRs => "c2pa-rs Reader, sequential stream".to_string(),
            Self::Sequential => "state-machine, sequential host".to_string(),
            Self::Concurrent {
                workers,
                chunk,
                readahead,
                window,
            } => format!(
                "state-machine, concurrent, {workers}w, {} KiB chunks, window {}, {}",
                chunk.get() / 1024,
                window.get(),
                if readahead.is_some() {
                    "readahead"
                } else {
                    "no readahead"
                },
            ),
        }
    }

    fn run(&self, store: &Arc<Store>, block: u64) -> Result<String, String> {
        let settings = |chunk: ChunkSize, window: HashWindow| ReadSettings {
            hash_chunk_size: chunk,
            hash_window: window,
            ..ReadSettings::default()
        };

        match self {
            Self::C2paRs => c2pa_rs(store, block),
            Self::Sequential => state_machine_sequential(
                store,
                block,
                settings(ChunkSize::clamped(block), HashWindow::default()),
            ),
            Self::Concurrent {
                workers,
                chunk,
                readahead,
                window,
            } => state_machine_concurrent(store, *workers, settings(*chunk, *window), *readahead),
        }
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse()?;
    let block = options.block_kib * 1024;

    eprintln!("signing a {} MiB asset...", options.size_mib);
    let asset = signed_asset(options.size_mib * 1024 * 1024)?;

    let store = Arc::new(Store::new(
        asset,
        Duration::from_millis(options.latency_ms),
        (options.mib_per_sec > 0.0).then_some(options.mib_per_sec * 1024.0 * 1024.0),
    ));

    println!(
        "asset {:.1} MiB | latency {} ms | {} per connection | readahead block {} KiB | median of {} run(s)\n",
        store.bytes.len() as f64 / (1024.0 * 1024.0),
        options.latency_ms,
        if options.mib_per_sec > 0.0 {
            format!("{} MiB/s", options.mib_per_sec)
        } else {
            "unlimited bandwidth".to_string()
        },
        options.block_kib,
        options.runs,
    );

    // The concurrent rows at the block size sweep the worker count (with
    // readahead, the realistic host); one no-readahead row shows what the
    // serial parse phase costs without it; the rest hold the workers at the
    // engine's window and sweep chunk size. Workers past the engine's
    // window of 8 are included when asked for (`--max-workers`) to show
    // they add no in-flight concurrency, not to speed anything up.
    let block_chunk = ChunkSize::clamped(block);
    let mut worker_counts = Vec::new();
    let mut w = 1;
    while w < options.max_workers {
        worker_counts.push(w);
        w *= 2;
    }
    worker_counts.push(options.max_workers);

    let mut scenarios = vec![Scenario::C2paRs, Scenario::Sequential];
    for workers in worker_counts {
        scenarios.push(Scenario::Concurrent {
            workers,
            chunk: block_chunk,
            readahead: Some(block),
            window: HashWindow::default(),
        });
    }
    scenarios.push(Scenario::Concurrent {
        workers: 8,
        chunk: block_chunk,
        readahead: None,
        window: HashWindow::default(),
    });
    for kib in [64, 256, 4096] {
        let chunk = ChunkSize::new(kib * 1024).map_err(|err| err.to_string())?;
        if chunk != block_chunk {
            scenarios.push(Scenario::Concurrent {
                workers: 8,
                chunk,
                readahead: Some(block),
                window: HashWindow::default(),
            });
        }
    }

    // Sweep the engine's in-flight window past its default of 8, at a small
    // chunk size so 8 chunks is a shallow pipeline the deeper window can
    // outrun. Workers match the window, so the limit under test is the
    // window, not the thread count.
    let small_chunk = ChunkSize::new(64 * 1024).map_err(|err| err.to_string())?;
    for chunks in [8usize, 16, 32] {
        let window = HashWindow::clamped(chunks);
        scenarios.push(Scenario::Concurrent {
            workers: chunks,
            chunk: small_chunk,
            readahead: Some(block),
            window,
        });
    }

    println!(
        "{:<70} {:>9} {:>9} {:>5} {:>8}  state",
        "scenario", "time", "requests", "peak", "speedup"
    );

    let mut baseline = None;
    let mut invalid = false;
    for scenario in &scenarios {
        let mut runs = Vec::new();
        for _ in 0..options.runs {
            runs.push(timed(&store, || scenario.run(&store, block))?);
        }
        let outcome = median(&mut runs);

        let baseline = *baseline.get_or_insert(outcome.elapsed);
        invalid |= outcome.state == "Invalid";

        println!(
            "{:<70} {:>8.2}s {:>9} {:>5} {:>7.2}x  {}",
            scenario.label(),
            outcome.elapsed.as_secs_f64(),
            outcome.requests,
            outcome.peak,
            baseline.as_secs_f64() / outcome.elapsed.as_secs_f64(),
            outcome.state,
        );
    }

    println!("\nspeedup is against the c2pa-rs row; peak is the most requests ever in flight.");

    if invalid {
        return Err("a reader found the signed asset invalid".to_string());
    }
    Ok(())
}
