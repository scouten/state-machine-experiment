//! Times the variants in the library on WAV files of several sizes.
//!
//! ```sh
//! cargo run --release -- --sizes 1,100,1024 --runs 5
//! ```
//!
//! Sizes are in MiB; a RIFF chunk cannot pass 4 GiB. Files are written under
//! `--dir` (default: the system temporary directory) and removed as the
//! run goes. Every run is on a warm page cache — the file was just written —
//! so these numbers are CPU and memory bandwidth, not a disk's.

use std::{path::PathBuf, time::Duration};

use asset_io_comparison::{
    asset_io, copy_only, floor, floor_pipelined, hash_only, make_wav, one_pass, reads_back_trusted,
    scratch_dir, two_pass, Run,
};

const MIB: f64 = 1024.0 * 1024.0;

struct Args {
    sizes: Vec<u64>,
    runs: usize,
    dir: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut args = Args {
        sizes: vec![1, 100, 1024],
        runs: 5,
        dir: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--sizes" => {
                args.sizes = it
                    .next()
                    .expect("--sizes needs a value")
                    .split(',')
                    .map(|s| s.parse().expect("sizes are whole MiB"))
                    .collect();
            }
            "--runs" => args.runs = it.next().expect("--runs needs a value").parse().unwrap(),
            "--dir" => args.dir = it.next().map(PathBuf::from),
            other => panic!("unknown argument {other}"),
        }
    }
    args
}

fn median(mut times: Vec<Duration>) -> Duration {
    times.sort();
    times[times.len() / 2]
}

/// One variant, run on demand: its name and the function that runs it.
type Variant = (&'static str, Box<dyn Fn() -> Run>);

struct Row {
    name: &'static str,
    time: Duration,
    read: u64,
    written: u64,
}

fn main() {
    let args = parse_args();
    let dir = scratch_dir(args.dir.clone());

    println!("scratch directory: {}", dir.display());
    println!("runs per variant: {} (median reported)\n", args.runs);

    for size in &args.sizes {
        let source = dir.join("source.wav");
        let output = dir.join("output.wav");
        make_wav(&source, size * 1024 * 1024).unwrap();
        let len = std::fs::metadata(&source).unwrap().len();

        // How big a manifest the real builder leaves room for.
        let first = one_pass(&source, &output).unwrap();
        if *size <= 100 {
            assert!(
                reads_back_trusted(&output),
                "one_pass output must read back"
            );
        }
        let manifest_len = first.manifest_len;

        let variants: [Variant; 5] = [
            (
                "this workspace, one pass (FileBuilderSession)",
                Box::new({
                    let (s, o) = (source.clone(), output.clone());
                    move || one_pass(&s, &o).unwrap()
                }),
            ),
            (
                "this workspace, two passes (hash read back)",
                Box::new({
                    let (s, o) = (source.clone(), output.clone());
                    move || two_pass(&s, &o).unwrap()
                }),
            ),
            (
                "asset-io (write_with_processing)",
                Box::new({
                    let (s, o) = (source.clone(), output.clone());
                    move || asset_io(&s, &o, manifest_len).unwrap()
                }),
            ),
            (
                "floor: read, hash, write",
                Box::new({
                    let (s, o) = (source.clone(), output.clone());
                    move || floor(&s, &o).unwrap()
                }),
            ),
            (
                "floor, hashing on a second thread",
                Box::new({
                    let (s, o) = (source.clone(), output.clone());
                    move || floor_pipelined(&s, &o).unwrap()
                }),
            ),
        ];

        // One discarded run of each: it creates the output file and brings
        // the source into the page cache.
        for (_, variant) in &variants {
            variant();
        }

        // Rotate the order each round so no variant always runs first (and
        // so pays for a cold cache) or always last.
        let mut times: Vec<Vec<Duration>> = vec![Vec::new(); variants.len()];
        let mut last: Vec<Option<Run>> = vec![None; variants.len()];
        for round in 0..args.runs {
            for step in 0..variants.len() {
                let i = (step + round) % variants.len();
                let run = (variants[i].1)();
                times[i].push(run.elapsed);
                last[i] = Some(run);
            }
        }

        if *size <= 100 {
            two_pass(&source, &output).unwrap();
            assert!(
                reads_back_trusted(&output),
                "two_pass output must read back"
            );
        }

        let copy = median(
            (0..args.runs)
                .map(|_| copy_only(&source, &output).unwrap())
                .collect(),
        );
        let hash = median(
            (0..args.runs)
                .map(|_| hash_only(&source).unwrap())
                .collect(),
        );

        let rows: Vec<Row> = variants
            .iter()
            .enumerate()
            .map(|(i, (name, _))| {
                let run = last[i].clone().unwrap();
                Row {
                    name,
                    time: median(times[i].clone()),
                    read: run.read,
                    written: run.written,
                }
            })
            .collect();
        let floor_time = rows[3].time;

        println!(
            "## {:.0} MiB WAV ({} bytes), manifest {} bytes\n",
            len as f64 / MIB,
            len,
            manifest_len
        );
        println!("| variant | median | MiB/s | read MiB | written MiB | vs floor |");
        println!("|---|---:|---:|---:|---:|---:|");
        for row in &rows {
            println!(
                "| {} | {:.1} ms | {:.0} | {:.1} | {:.1} | {:.2}x |",
                row.name,
                row.time.as_secs_f64() * 1e3,
                len as f64 / MIB / row.time.as_secs_f64(),
                row.read as f64 / MIB,
                row.written as f64 / MIB,
                row.time.as_secs_f64() / floor_time.as_secs_f64(),
            );
        }
        println!(
            "\nceilings: copy alone {:.1} ms ({:.0} MiB/s), SHA-256 alone {:.1} ms ({:.0} MiB/s)\n",
            copy.as_secs_f64() * 1e3,
            len as f64 / MIB / copy.as_secs_f64(),
            hash.as_secs_f64() * 1e3,
            len as f64 / MIB / hash.as_secs_f64(),
        );

        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&output);
    }

    let _ = std::fs::remove_dir(&dir);
}
