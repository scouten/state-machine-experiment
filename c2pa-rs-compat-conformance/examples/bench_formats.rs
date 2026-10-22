//! Performance comparison: signing and validation of JPEG and TIFF/DNG
//! assets, the state-machine SDK against the real `c2pa` crate, over the
//! c2pa-rs fixture corpus.
//!
//! ```sh
//! cargo run --release --example bench_formats
//! cargo run --release --example bench_formats -- --iterations 9 \
//!     --fixtures /path/to/c2pa-rs/sdk/tests/fixtures
//! ```
//!
//! # What is measured
//!
//! For every JPEG and TIFF/DNG fixture, two workflows on each SDK:
//!
//! * **Sign** — add an ES256 content-credential manifest to the asset,
//!   through each SDK's idiomatic *file* entry point (state-machine
//!   [`build_and_sign_file`], c2pa-rs [`Builder::sign_file`]).
//! * **Validate** — read and validate that manifest back, again file-based
//!   (state-machine [`read_manifest_from_file`], c2pa-rs
//!   [`Reader::with_file`]). The input is the asset *as freshly signed by
//!   the state-machine SDK*, so both readers validate identical, known-good
//!   bytes and do the full hash + signature + chain work; the final trust
//!   verdict (the test signer is untrusted) is incidental to the cost.
//!
//! Each operation reports the **median wall-clock time** over `--iterations`
//! runs (after one warm-up) and the **peak additional heap** it held,
//! captured by a tracking global allocator. Peak heap — not whole-process
//! RSS — is what makes the two SDKs comparable and exposes streaming versus
//! whole-asset buffering, which is why the large DNGs are in the corpus.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::{Duration, Instant},
};

use contentauth_c2pa_file_builder::{build_and_sign_file, HostError, SigningAlg};
use contentauth_c2pa_file_reader::{read_manifest_from_file, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_format_tiff::TiffFormat;
use contentauth_c2pa_sign_baseline::{
    fixtures::{TEST_SIGNER_CERT, TEST_SIGNER_KEY_PEM},
    Definition, BASELINE_DEFINITION,
};

// ---------------------------------------------------------------------------
// Peak-heap tracking allocator.
// ---------------------------------------------------------------------------

/// Live bytes currently allocated through the global allocator.
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of [`LIVE`] since the last [`reset_peak`].
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Tracking;

// SAFETY: every path forwards to the system allocator unchanged; the atomics
// only observe sizes and never affect the returned pointers.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let now = LIVE.fetch_add(layout.size(), Relaxed) + layout.size();
            PEAK.fetch_max(now, Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            let now = LIVE.fetch_add(new_size, Relaxed) + new_size;
            PEAK.fetch_max(now, Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

/// Arms the peak counter at the current live level; the returned base is
/// subtracted from the peak afterwards to give the operation's own peak.
fn arm_peak() -> usize {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    base
}

/// Peak additional bytes held since [`arm_peak`] returned `base`.
fn peak_since(base: usize) -> usize {
    PEAK.load(Relaxed).saturating_sub(base)
}

// ---------------------------------------------------------------------------
// One measured sample: median time and peak heap over N iterations.
// ---------------------------------------------------------------------------

struct Sample {
    median: Duration,
    peak_bytes: usize,
    note: String,
}

/// Runs `op` once to warm up, then `iterations` more times, returning the
/// median elapsed time and the largest per-run peak heap. `op` returns a
/// short note (e.g. the validation state) carried into the report; a failure
/// is reported in the note and stops further iterations.
fn measure(iterations: usize, mut op: impl FnMut() -> Result<String, String>) -> Sample {
    // Warm up (fills caches, resolves lazy statics) and surface early errors.
    let note = match op() {
        Ok(note) => note,
        Err(err) => {
            return Sample {
                median: Duration::ZERO,
                peak_bytes: 0,
                note: format!("ERR: {err}"),
            }
        }
    };

    let mut times = Vec::with_capacity(iterations);
    let mut peak_bytes = 0usize;
    for _ in 0..iterations {
        let base = arm_peak();
        let started = Instant::now();
        let result = op();
        let elapsed = started.elapsed();
        peak_bytes = peak_bytes.max(peak_since(base));
        if let Err(err) = result {
            return Sample {
                median: Duration::ZERO,
                peak_bytes,
                note: format!("ERR: {err}"),
            };
        }
        times.push(elapsed);
    }
    times.sort_unstable();
    Sample {
        median: times[times.len() / 2],
        peak_bytes,
        note,
    }
}

// ---------------------------------------------------------------------------
// The two SDKs, four operations.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Fmt {
    Jpeg,
    Tiff,
}

fn settings() -> contentauth_c2pa_file_builder::BuilderSettings {
    Definition::from_json(BASELINE_DEFINITION)
        .and_then(|definition| {
            definition.into_settings(SigningAlg::Es256, vec![TEST_SIGNER_CERT.to_vec()])
        })
        .expect("baseline definition builds settings")
}

/// Raw ES256 signature over `data`, re-parsing the key each call (cheap next
/// to the hash); mirrors what any host callback does.
fn sm_sign_bytes(data: &[u8]) -> Result<Vec<u8>, HostError> {
    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .map_err(|err| HostError::new(err.to_string()))?;
    signer
        .sign(data)
        .map_err(|err| HostError::new(err.to_string()))
}

fn sm_sign(fmt: Fmt, source: &Path, dest: &Path) -> Result<String, String> {
    let _ = std::fs::remove_file(dest);
    let report = match fmt {
        Fmt::Jpeg => build_and_sign_file(
            JpegFormat,
            source,
            dest,
            settings(),
            |_alg, data| sm_sign_bytes(data),
            None,
            None,
        ),
        Fmt::Tiff => build_and_sign_file(
            TiffFormat,
            source,
            dest,
            settings(),
            |_alg, data| sm_sign_bytes(data),
            None,
            None,
        ),
    }
    .map_err(|err| err.to_string())?;
    let _ = report;
    Ok("signed".to_string())
}

fn sm_validate(fmt: Fmt, path: &Path) -> Result<String, String> {
    let report = match fmt {
        Fmt::Jpeg => read_manifest_from_file(&JpegFormat, path, ReadSettings::default()),
        Fmt::Tiff => read_manifest_from_file(&TiffFormat, path, ReadSettings::default()),
    }
    .map_err(|err| err.to_string())?;
    Ok(format!("{:?}", report.validation_state))
}

fn c2pa_rs_sign(source: &Path, dest: &Path) -> Result<String, String> {
    let _ = std::fs::remove_file(dest);
    // c2pa-rs wants a PEM certificate; `TEST_SIGNER_CERT` is the DER form of
    // the same signer, so this is the matching PEM encoding and the same key.
    let signer = c2pa::create_signer::from_keys(
        C2PA_RS_SIGNER_CERT_PEM,
        TEST_SIGNER_KEY_PEM,
        c2pa::SigningAlg::Es256,
        None,
    )
    .map_err(|err| err.to_string())?;
    // The test signer is untrusted; verify-after-sign would reject it, but
    // all we want to measure is assembling and writing the manifest.
    let context = c2pa::Context::new()
        .with_settings(r#"{"verify": {"verify_after_sign": false}}"#)
        .map_err(|err| err.to_string())?;
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(C2PA_RS_DEFINITION)
        .map_err(|err| err.to_string())?;
    builder
        .sign_file(signer.as_ref(), source, dest)
        .map_err(|err| err.to_string())?;
    Ok("signed".to_string())
}

fn c2pa_rs_validate(path: &Path) -> Result<String, String> {
    let reader = c2pa::Reader::from_context(c2pa::Context::new())
        .with_file(path)
        .map_err(|err| err.to_string())?;
    Ok(match reader.validation_state() {
        c2pa::ValidationState::Trusted => "Trusted",
        c2pa::ValidationState::Valid => "Valid",
        c2pa::ValidationState::Invalid => "Invalid",
    }
    .to_string())
}

/// c2pa-rs wants a PEM certificate; this is the PEM encoding of the same
/// signer whose DER form the state-machine side uses as `TEST_SIGNER_CERT`.
const C2PA_RS_SIGNER_CERT_PEM: &[u8] = include_bytes!("../tests/fixtures/test-signer.pem");

/// The baseline claim, in c2pa-rs's own definition shape (one `c2pa.created`
/// action), so only the container and the signing cost differ between SDKs.
const C2PA_RS_DEFINITION: &str = r#"{
  "title": "bench",
  "assertions": [{
    "label": "c2pa.actions.v2",
    "data": {"actions": [{
      "action": "c2pa.created",
      "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
    }]}
  }]
}"#;

// ---------------------------------------------------------------------------
// Reporting.
// ---------------------------------------------------------------------------

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

struct Row {
    fmt: &'static str,
    asset: String,
    size: u64,
    sm: Sample,
    rs: Sample,
}

fn print_table(title: &str, rows: &[Row]) {
    println!("\n=== {title} ===");
    println!(
        "{:<5} {:<30} {:>9} | {:>9} {:>10} | {:>9} {:>10} | {:>7} {:>7}",
        "fmt", "asset", "size", "sm ms", "sm mem", "rs ms", "rs mem", "t rs/sm", "m rs/sm"
    );
    for r in rows {
        let (sm_ok, rs_ok) = (!r.sm.note.starts_with("ERR"), !r.rs.note.starts_with("ERR"));
        let t_ratio = if sm_ok && rs_ok && ms(r.sm.median) > 0.0 {
            format!("{:.2}x", ms(r.rs.median) / ms(r.sm.median))
        } else {
            "-".to_string()
        };
        let m_ratio = if sm_ok && rs_ok && r.sm.peak_bytes > 0 {
            format!("{:.2}x", r.rs.peak_bytes as f64 / r.sm.peak_bytes as f64)
        } else {
            "-".to_string()
        };
        let sm_ms = if sm_ok {
            format!("{:.2}", ms(r.sm.median))
        } else {
            "ERR".to_string()
        };
        let rs_ms = if rs_ok {
            format!("{:.2}", ms(r.rs.median))
        } else {
            "ERR".to_string()
        };
        println!(
            "{:<5} {:<30} {:>9} | {:>9} {:>10} | {:>9} {:>10} | {:>7} {:>7}",
            r.fmt,
            truncate(&r.asset, 30),
            human_bytes(r.size),
            sm_ms,
            human_bytes(r.sm.peak_bytes as u64),
            rs_ms,
            human_bytes(r.rs.peak_bytes as u64),
            t_ratio,
            m_ratio,
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

fn fixtures_default() -> PathBuf {
    [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "c2pa-rs",
        "sdk",
        "tests",
        "fixtures",
    ]
    .iter()
    .collect()
}

fn collect(dir: &Path) -> Vec<(Fmt, PathBuf)> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let fmt = match ext.as_str() {
            "jpg" | "jpeg" => Fmt::Jpeg,
            "tif" | "tiff" | "dng" => Fmt::Tiff,
            _ => continue,
        };
        out.push((fmt, path));
    }
    out.sort_by(|a, b| {
        (a.0 == Fmt::Tiff, a.1.file_name()).cmp(&(b.0 == Fmt::Tiff, b.1.file_name()))
    });
    out
}

fn main() {
    let mut iterations = 7usize;
    let mut fixtures = fixtures_default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iterations" => {
                iterations = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(iterations)
            }
            "--fixtures" => fixtures = args.next().map(PathBuf::from).unwrap_or(fixtures),
            other => eprintln!("ignoring unknown arg: {other}"),
        }
    }

    let assets = collect(&fixtures);
    println!(
        "Benchmarking {} assets from {}\nES256, median of {} iterations (after 1 warm-up), peak additional heap.",
        assets.len(),
        fixtures.display(),
        iterations,
    );

    let tmp = std::env::temp_dir().join(format!("bench_formats_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("create temp dir");

    let mut sign_rows = Vec::new();
    let mut validate_rows = Vec::new();

    for (fmt, path) in &assets {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let fmt_label = if *fmt == Fmt::Jpeg { "JPEG" } else { "TIFF" };
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("bin");
        eprintln!("  {name}");

        // --- Sign (each SDK writes its own output) ---
        let sm_out = tmp.join(format!("{name}.sm.{ext}"));
        let rs_out = tmp.join(format!("{name}.rs.{ext}"));
        let sm_sign_sample = measure(iterations, || sm_sign(*fmt, path, &sm_out));
        let rs_sign_sample = measure(iterations, || c2pa_rs_sign(path, &rs_out));
        sign_rows.push(Row {
            fmt: fmt_label,
            asset: name.clone(),
            size,
            sm: sm_sign_sample,
            rs: rs_sign_sample,
        });

        // --- Validate the state-machine-signed output with both SDKs ---
        // (Identical bytes to both readers; skip if the SM could not sign.)
        if sm_out.exists() {
            let validate_size = std::fs::metadata(&sm_out).map(|m| m.len()).unwrap_or(size);
            let sm_val = measure(iterations, || sm_validate(*fmt, &sm_out));
            let rs_val = measure(iterations, || c2pa_rs_validate(&sm_out));
            validate_rows.push(Row {
                fmt: fmt_label,
                asset: name.clone(),
                size: validate_size,
                sm: sm_val,
                rs: rs_val,
            });
        }
    }

    print_table("SIGNING (ES256, file-based)", &sign_rows);
    print_table(
        "VALIDATION (of state-machine-signed output, file-based)",
        &validate_rows,
    );

    summarize("SIGNING", &sign_rows);
    summarize("VALIDATION", &validate_rows);

    let _ = std::fs::remove_dir_all(&tmp);
}

/// Geometric-mean ratios over the rows where both SDKs succeeded, per format.
fn summarize(title: &str, rows: &[Row]) {
    println!("\n--- {title}: geomean (rs/sm) over successful rows ---");
    for (label, fmt) in [("JPEG", "JPEG"), ("TIFF/DNG", "TIFF")] {
        let ok: Vec<&Row> = rows
            .iter()
            .filter(|r| {
                r.fmt == fmt
                    && !r.sm.note.starts_with("ERR")
                    && !r.rs.note.starts_with("ERR")
                    && ms(r.sm.median) > 0.0
                    && r.sm.peak_bytes > 0
            })
            .collect();
        if ok.is_empty() {
            println!("  {label}: no comparable rows");
            continue;
        }
        let gm = |values: &[f64]| -> f64 {
            let sum: f64 = values.iter().map(|v| v.ln()).sum();
            (sum / values.len() as f64).exp()
        };
        let t: Vec<f64> = ok
            .iter()
            .map(|r| ms(r.rs.median) / ms(r.sm.median))
            .collect();
        let m: Vec<f64> = ok
            .iter()
            .map(|r| r.rs.peak_bytes as f64 / r.sm.peak_bytes as f64)
            .collect();
        println!(
            "  {label}: {} assets  time rs/sm {:.2}x  mem rs/sm {:.2}x",
            ok.len(),
            gm(&t),
            gm(&m),
        );
    }
}
