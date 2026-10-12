//! Signing a large RIFF file, four ways, to answer one question: does this
//! workspace's `FileBuilderSession` do the work of Gavin Peacock's
//! `asset-io` `write_with_processing` — read the source once, write the
//! output once, hash on the way — and what did the old shape, which read the
//! output back to hash it, cost by comparison?
//!
//! Every variant does the same job for a WAV on disk: write a copy with a
//! C2PA chunk of the same size in it, hash everything outside that chunk
//! with SHA-256, sign the hash, and put the signature's manifest in the
//! chunk. They differ only in how many times they touch the file.
//!
//! * [`two_pass`] — `BuilderSession` in its pull mode, driven by a host that
//!   copies the plan's edits to the output and then, when asked for
//!   `AssetBytes`, reads the output back. The shape `FileBuilderSession`
//!   had before it hashed as it wrote.
//! * [`one_pass`] — `contentauth_c2pa_file_builder::build_and_sign`.
//! * [`asset_io`] — `asset_io::Asset::write_with_processing`, a SHA-256
//!   hasher in the callback, and `Structure::update_segment`.
//! * [`floor`] — the least any of the above could do: read a chunk, hash it,
//!   write it, with no format handling at all.
//!
//! Only [`two_pass`] and [`one_pass`] produce a manifest `contentauth-c2pa-reader`
//! accepts; [`asset_io`] stands in a same-sized blob for one (this crate has
//! no business building a C2PA manifest with someone else's library), so it
//! is a measurement of I/O and hashing, not of signing.

#![allow(clippy::unwrap_used)]

use std::{
    cell::Cell,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep, GeneratorInfo,
    SigningAlg,
};
use contentauth_c2pa_file_builder::{build_and_sign, HostError};
use contentauth_c2pa_format::{Edit, FormatHandler, IoReply, IoRequest, StreamId};
use contentauth_c2pa_format_riff::RiffFormat;
use contentauth_state_machine::Session;
use sha2::{Digest, Sha256};

const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

/// How much each variant moves at a time, where it chooses: the same
/// 1 MiB `FileBuilderSession` copies in.
const CHUNK: usize = 1 << 20;

pub fn settings() -> BuilderSettings {
    BuilderSettings::new(
        "xmp:iid:bench-instance",
        "urn:uuid:bench-manifest",
        GeneratorInfo::new("asset-io-comparison", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    )
}

pub fn sign(alg: SigningAlg, data: &[u8]) -> Result<Vec<u8>, HostError> {
    assert_eq!(alg, SigningAlg::Es256);
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .map_err(|err| HostError::new(err.to_string()))?;
    signer
        .sign(data)
        .map_err(|err| HostError::new(err.to_string()))
}

pub fn trust_anchor() -> Vec<u8> {
    TEST_SIGNER_CERT.to_vec()
}

/// Bytes moved, as the variant's own code saw them.
#[derive(Clone, Debug, Default)]
pub struct Io {
    pub read: Rc<Cell<u64>>,
    pub written: Rc<Cell<u64>>,
}

/// A file that tallies what is read from and written to it.
pub struct Counted {
    file: File,
    io: Io,
}

impl Counted {
    pub fn new(file: File, io: &Io) -> Self {
        Self {
            file,
            io: io.clone(),
        }
    }
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        self.io.read.set(self.io.read.get() + n as u64);
        Ok(n)
    }
}

impl Write for Counted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.io.written.set(self.io.written.get() + n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for Counted {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

/// Opens `path` for writing without truncating it.
///
/// The benchmark rewrites the same output over and over at the same length,
/// and truncating a file first would hand every run a fresh allocation of
/// the file's pages to fault in — noise that, on the virtual machines these
/// are run on, dwarfs the difference between variants. Overwriting in place
/// measures reading, hashing and copying instead. (The first run of each
/// variant, which creates the file, is a discarded warm-up.)
pub fn open_output(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// What one run of a variant did.
#[derive(Clone, Debug)]
pub struct Run {
    pub elapsed: Duration,
    pub read: u64,
    pub written: u64,
    pub manifest_len: usize,
}

/// Writes a WAV of `len` bytes (or a little more): a PCM `fmt ` chunk, a
/// `data` chunk of deterministic audio, and a trailing `LIST` chunk, as
/// many writers leave.
pub fn make_wav(path: &Path, len: u64) -> io::Result<()> {
    let mut out = io::BufWriter::with_capacity(CHUNK, File::create(path)?);

    let mut fmt = vec![1, 0, 1, 0];
    fmt.extend(8000u32.to_le_bytes());
    fmt.extend(8000u32.to_le_bytes());
    fmt.extend([1, 0, 8, 0]);
    let list = b"INFOISFT\x04\0\0\0abc\0";

    // The RIFF size field is 32 bits: a WAV cannot pass 4 GiB.
    let data_len = len.min(u64::from(u32::MAX) - 1024);
    let data_len = data_len & !1;
    let riff_size = 4 + (8 + fmt.len() as u64) + (8 + data_len) + (8 + list.len() as u64);

    out.write_all(b"RIFF")?;
    out.write_all(&(riff_size as u32).to_le_bytes())?;
    out.write_all(b"WAVE")?;
    out.write_all(b"fmt ")?;
    out.write_all(&(fmt.len() as u32).to_le_bytes())?;
    out.write_all(&fmt)?;
    out.write_all(b"data")?;
    out.write_all(&(data_len as u32).to_le_bytes())?;

    let mut block = vec![0u8; CHUNK];
    let mut written = 0u64;
    while written < data_len {
        let n = (data_len - written).min(CHUNK as u64) as usize;
        for (i, byte) in block[..n].iter_mut().enumerate() {
            *byte = ((written + i as u64) % 251) as u8;
        }
        out.write_all(&block[..n])?;
        written += n as u64;
    }

    out.write_all(b"LIST")?;
    out.write_all(&(list.len() as u32).to_le_bytes())?;
    out.write_all(list)?;
    out.flush()
}

/// `FileBuilderSession` through its synchronous host: the source read once,
/// the output written once, the hash accumulated on the way.
pub fn one_pass(source: &Path, output: &Path) -> io::Result<Run> {
    let io = Io::default();
    let source = Counted::new(File::open(source)?, &io);
    let output = Counted::new(open_output(output)?, &io);

    let start = Instant::now();
    let report = build_and_sign(RiffFormat, source, output, settings(), sign, None, None).unwrap();
    let elapsed = start.elapsed();

    Ok(Run {
        elapsed,
        read: io.read.get(),
        written: io.written.get(),
        manifest_len: report.manifest.len(),
    })
}

/// Answers a handler operation's `IoRequest`s from a file.
fn run_op<S>(file: &mut File, mut op: S) -> S::Output
where
    S: Session<Request = IoRequest>,
    S::Error: std::fmt::Debug,
{
    loop {
        if op.advance().unwrap() == contentauth_state_machine::Step::Complete {
            return op.finish().unwrap();
        }
        for request in op.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                IoRequest::Length { .. } => IoReply::Length(file.seek(SeekFrom::End(0)).unwrap()),
                IoRequest::Read { range, .. } => {
                    file.seek(SeekFrom::Start(range.start)).unwrap();
                    let mut buf = vec![0u8; range.len as usize];
                    file.read_exact(&mut buf).unwrap();
                    IoReply::Bytes(buf)
                }
                _ => panic!("unexpected request"),
            };
            op.fulfill(request.id, reply).unwrap();
        }
    }
}

/// The shape `FileBuilderSession` had before it hashed as it wrote:
/// `BuilderSession` in pull mode, a host that copies the plan to the output
/// and, when asked for the asset's bytes to hash, reads the output back.
pub fn two_pass(source_path: &Path, output_path: &Path) -> io::Result<Run> {
    let io = Io::default();
    let mut source = Counted::new(File::open(source_path)?, &io);
    let mut output = Counted::new(open_output(output_path)?, &io);
    let mut plan_source = File::open(source_path)?;

    let start = Instant::now();
    let mut session = BuilderSession::new(settings());
    let mut plan = None;
    let mut manifest_len = 0;

    loop {
        if session.advance().unwrap() == BuilderStep::Complete {
            manifest_len = manifest_len.max(session.finish().unwrap().manifest.len());
            break;
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                    let embed_plan = run_op(
                        &mut plan_source,
                        RiffFormat.plan_embed(StreamId::new(0), placeholder.len() as u64),
                    );

                    let mut offset = 0u64;
                    for edit in &embed_plan.edits {
                        output.seek(SeekFrom::Start(offset)).unwrap();
                        match edit {
                            Edit::Copy(range) => {
                                let mut done = 0;
                                let mut buf = vec![0u8; CHUNK];
                                source.seek(SeekFrom::Start(range.start)).unwrap();
                                while done < range.len {
                                    let n = (range.len - done).min(CHUNK as u64) as usize;
                                    source.read_exact(&mut buf[..n]).unwrap();
                                    output.write_all(&buf[..n]).unwrap();
                                    done += n as u64;
                                }
                            }
                            Edit::Emit(bytes) => output.write_all(bytes).unwrap(),
                            Edit::Placeholder(range) => output
                                .write_all(
                                    &placeholder[range.start as usize..][..range.len as usize],
                                )
                                .unwrap(),
                            _ => panic!("unsupported edit"),
                        }
                        offset += edit.len();
                    }

                    let exclusions = embed_plan.exclusions.clone();
                    plan = Some(embed_plan);
                    BuilderHostReply::PlaceholderReserved {
                        exclusions,
                        hash: None,
                    }
                }
                BuilderRequest::AssetLength { .. } => {
                    BuilderHostReply::AssetLength(plan.as_ref().unwrap().output_len().unwrap())
                }
                BuilderRequest::AssetBytes { range, .. } => {
                    output.seek(SeekFrom::Start(range.start)).unwrap();
                    let mut buf = vec![0u8; range.len as usize];
                    output.read_exact(&mut buf).unwrap();
                    BuilderHostReply::AssetBytes(buf)
                }
                BuilderRequest::Sign { alg, data, .. } => match sign(*alg, data) {
                    Ok(signature) => BuilderHostReply::Signature(signature),
                    Err(err) => BuilderHostReply::Failed(err),
                },
                BuilderRequest::CommitManifest { manifest, .. } => {
                    let embed_plan = plan.as_ref().unwrap();
                    manifest_len = manifest.len();
                    let mut offset = 0u64;
                    for edit in &embed_plan.edits {
                        if let Edit::Placeholder(range) = edit {
                            output.seek(SeekFrom::Start(offset)).unwrap();
                            output
                                .write_all(&manifest[range.start as usize..][..range.len as usize])
                                .unwrap();
                        }
                        offset += edit.len();
                    }
                    output.flush().unwrap();
                    BuilderHostReply::ManifestCommitted
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
    let elapsed = start.elapsed();

    Ok(Run {
        elapsed,
        read: io.read.get(),
        written: io.written.get(),
        manifest_len,
    })
}

/// asset-io's single pass: `write_with_processing` with a SHA-256 hasher in
/// the callback, a "signature" over the digest, and the manifest patched in
/// place with `update_segment`. `manifest_len` is the size of the C2PA
/// chunk to leave room for.
pub fn asset_io(source: &Path, output: &Path, manifest_len: usize) -> io::Result<Run> {
    use asset_io::{Asset, ExclusionMode, ProcessChunk, SegmentKind, Updates};

    let io = Io::default();
    let source = Counted::new(File::open(source)?, &io);
    let mut output = Counted::new(open_output(output)?, &io);

    let start = Instant::now();
    let mut asset = Asset::from_source(source).unwrap();
    let updates = Updates::new()
        .set_jumbf(vec![0u8; manifest_len])
        .exclude_from_processing(vec![SegmentKind::Jumbf], ExclusionMode::DataOnly);

    let mut hasher = Sha256::new();
    let structure = asset
        .write_with_processing(&mut output, &updates, &mut |chunk: &dyn ProcessChunk| {
            hasher.update(chunk.data());
            Ok(())
        })
        .unwrap();
    let digest = hasher.finalize();

    // Stand in for building and signing a manifest: sign the digest, and pad
    // the signature out to the room the placeholder left.
    let mut manifest = sign(SigningAlg::Es256, &digest).unwrap();
    manifest.resize(manifest_len, 0);
    structure
        .update_segment(&mut output, SegmentKind::Jumbf, manifest)
        .unwrap();
    output.flush().unwrap();
    let elapsed = start.elapsed();

    Ok(Run {
        elapsed,
        read: io.read.get(),
        written: io.written.get(),
        manifest_len,
    })
}

/// The least any variant could do: read a chunk, hash it, write it.
pub fn floor(source: &Path, output: &Path) -> io::Result<Run> {
    floor_chunked(source, output, CHUNK)
}

/// [`floor`], moving `chunk` bytes at a time. A chunk that fits the CPU's
/// L2 cache is hashed from cache after it is read and written from cache
/// after it is hashed; one that does not is read back from L3 or memory
/// twice, and that shows at the speeds SHA-256 runs.
pub fn floor_chunked(source: &Path, output: &Path, chunk: usize) -> io::Result<Run> {
    let io = Io::default();
    let mut source = Counted::new(File::open(source)?, &io);
    let mut output = Counted::new(open_output(output)?, &io);

    let start = Instant::now();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; chunk];
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output.write_all(&buf[..n])?;
    }
    output.flush()?;
    std::hint::black_box(hasher.finalize());
    let elapsed = start.elapsed();

    Ok(Run {
        elapsed,
        read: io.read.get(),
        written: io.written.get(),
        manifest_len: 0,
    })
}

/// [`floor`] with the hashing on its own thread: the main thread reads a
/// chunk and writes it while a second hashes the chunks, in order, as they
/// are handed over.
///
/// SHA-256 over one stream cannot be split across threads, but nothing says
/// the thread that hashes must be the one doing the I/O. This is the most
/// that overlapping the two could buy a single-stream hash such as
/// `c2pa.hash.data`'s: wall time falls toward the slower of hashing and
/// copying instead of their sum.
pub fn floor_pipelined(source: &Path, output: &Path) -> io::Result<Run> {
    use std::sync::{mpsc, Arc};

    let io = Io::default();
    let mut source = Counted::new(File::open(source)?, &io);
    let mut output = Counted::new(open_output(output)?, &io);

    let start = Instant::now();
    let (tx, rx) = mpsc::sync_channel::<Arc<Vec<u8>>>(4);
    let hasher = std::thread::spawn(move || {
        let mut hasher = Sha256::new();
        for chunk in rx {
            hasher.update(chunk.as_slice());
        }
        hasher.finalize()
    });

    loop {
        let mut buf = vec![0u8; CHUNK];
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        buf.truncate(n);
        let buf = Arc::new(buf);
        output.write_all(&buf)?;
        tx.send(buf).unwrap();
    }
    drop(tx);
    std::hint::black_box(hasher.join().unwrap());
    output.flush()?;
    let elapsed = start.elapsed();

    Ok(Run {
        elapsed,
        read: io.read.get(),
        written: io.written.get(),
        manifest_len: 0,
    })
}

/// Reading the file and nothing else; and hashing it and nothing else: the
/// two ceilings under [`floor`].
pub fn copy_only(source: &Path, output: &Path) -> io::Result<Duration> {
    let mut source = File::open(source)?;
    let mut output = open_output(output)?;
    let start = Instant::now();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }
    output.flush()?;
    Ok(start.elapsed())
}

pub fn hash_only(source: &Path) -> io::Result<Duration> {
    let mut source = File::open(source)?;
    let start = Instant::now();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    std::hint::black_box(hasher.finalize());
    Ok(start.elapsed())
}

/// Reads `path` back through this workspace's reader, trusting the test
/// signer, and reports whether the manifest validated as trusted.
pub fn reads_back_trusted(path: &Path) -> bool {
    use contentauth_c2pa_reader::{ReadSettings, ValidationState};

    let report = contentauth_c2pa_file_reader::read_manifest_from_file(
        &RiffFormat,
        path,
        ReadSettings {
            trust_anchors: vec![trust_anchor()],
            ..ReadSettings::default()
        },
    )
    .unwrap();
    report.validation_state == Some(ValidationState::Trusted)
}

pub fn scratch_dir(base: Option<PathBuf>) -> PathBuf {
    let dir = base
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("asset-io-comparison-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
