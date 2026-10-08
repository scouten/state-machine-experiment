# asset-io-comparison

Signing large RIFF files, four ways, to answer one question: does this
workspace's `FileBuilderSession` do the work of Gavin Peacock's
[`asset-io`](https://github.com/gpeacock/asset-io) `write_with_processing` —
read the source once, write the output once, hash on the way — and what did
the shape it replaced, which read the output back to hash it, cost by
comparison?

## Why this is its own, separate Cargo workspace

It takes a pinned git dependency on `asset-io`, which the root workspace's
checks (Wasm, MSRV, `cargo-deny`'s source allow-list) do not want swept in —
the same reason `c2pa-rs-compat-conformance` is separate.

## The variants

Every variant does the same job for a WAV on disk: write a copy with a
C2PA chunk of the same size in it, hash everything outside that chunk with
SHA-256, sign the hash, and put the manifest in the chunk.

| Variant | What it is |
|---|---|
| one pass | `contentauth_c2pa_file_builder::build_and_sign` with the RIFF handler. The hash is accumulated as the output is produced; the output is never read. |
| two passes | `BuilderSession` in its pull mode, driven by a host that copies the plan's edits to the output and then, asked for `AssetBytes`, reads the output back: the shape `FileBuilderSession` had before. |
| asset-io | `Asset::write_with_processing`, a SHA-256 hasher in the callback, and `Structure::update_segment`. It stands in a same-sized blob for a manifest (a signature, padded): this crate has no business building a C2PA manifest with someone else's library, so it measures I/O and hashing, not signing. |
| floor | Read a 1 MiB chunk, hash it, write it. No format handling at all. |
| floor, second thread | The same, with the hashing on its own thread. Not a variant of the workspace — a measure of what overlapping hashing with I/O could buy a single-stream digest. |

`tests/variants_agree.rs` checks the timed variants do the same job: this
workspace's outputs read back `Trusted`, and all three files are
byte-identical outside the manifest's data — including the one written by
`asset-io`'s code (same header, same size field, same chunks, same `C2PA`
chunk header).

## Running it

```sh
cargo run --release -- --sizes 1,100,1024 --runs 7 --dir /dev/shm
```

Sizes are MiB (a RIFF chunk cannot pass 4 GiB). `--dir` is where the files
go; a RAM-backed directory keeps the disk out of it. The output file is
overwritten in place rather than truncated and recreated between runs: on
the virtual machines this was written on, faulting in a fresh file's pages
swamped the difference between variants, and a discarded warm-up run
creates the file once.

## Results

One 4-vCPU Xeon container at 2.1 GHz, `/dev/shm`, warm page cache, median
of 7. Single run per size; ratios are stable between runs to a few percent,
absolute numbers are not (shared machine).

| size | one pass | two passes | asset-io | floor | floor, hash on 2nd thread |
|---:|---:|---:|---:|---:|---:|
| 100 MiB | 134 ms (1.03×) | 158 ms (1.21×) | 136 ms (1.04×) | 131 ms | 83 ms (0.63×) |
| 1 GiB | 1239 ms (1.04×) | 1438 ms (1.20×) | 1272 ms (1.07×) | 1194 ms | 815 ms (0.68×) |

(Ratios are against the floor.) Read: the one-pass build runs at the speed of
a bare read-hash-write loop, a few percent ahead of `asset-io`, and the
read-back shape costs about a fifth more and reads the file twice. Hashing
on a second thread would take about a third off all of them: SHA-256 over
one stream cannot be split, but it need not share a thread with the copy.

At 1 MiB every variant is dominated by fixed costs (about 2 ms against 1 ms
for the floor); `asset-io` is a little ahead there.

**Caveats.** Warm cache, tmpfs: this is CPU and memory bandwidth, not disk.
SHA-256 is hardware-accelerated here, which it will not be everywhere.
`asset-io` is hashed with `sha2` 0.10 and this workspace with 0.11. Neither
side was tuned for the benchmark.

One result worth recording: the first version of the one-pass host was
*slower* than the two-pass one (219 ms against 171 ms at 100 MiB) because
its loop cloned every outstanding request to get past the borrow checker,
copying each 1 MiB `Write` payload once more. Answering the requests while
borrowing them removed it.
