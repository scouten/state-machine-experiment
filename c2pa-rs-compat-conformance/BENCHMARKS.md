# Format performance: state-machine SDK vs c2pa-rs

This document records the signing and validation performance experiments
comparing this workspace's **state-machine SDK** against the real
[**c2pa-rs**](https://github.com/contentauth/c2pa-rs) crate, across the JPEG
and TIFF/DNG container formats, over c2pa-rs's own fixture corpus.

The experiment is reproducible via
[`examples/bench_formats.rs`](examples/bench_formats.rs):

```sh
cargo run --release --example bench_formats
# options:
cargo run --release --example bench_formats -- \
    --iterations 9 --fixtures /path/to/c2pa-rs/sdk/tests/fixtures
```

## Experiments performed

For every JPEG and TIFF/DNG fixture, two workflows are measured on **both**
SDKs, through each one's idiomatic **file-based** entry point:

| Workflow | state-machine SDK | c2pa-rs |
|---|---|---|
| **Sign** (add an ES256 content-credential manifest) | `build_and_sign_file` | `Builder::sign_file` |
| **Validate** (read + validate the manifest back) | `read_manifest_from_file` | `Reader::with_file` |

Both metrics are captured per operation:

- **Time** — median wall-clock over 7 iterations after 1 warm-up run.
- **Memory** — peak *additional* heap held during the operation, captured by
  a tracking `#[global_allocator]` (peak minus the pre-operation live level).
  Peak heap, not whole-process RSS, is what makes the two SDKs comparable and
  exposes streaming versus whole-asset buffering.

**Signing** uses ES256 with the shared test signer (the same key for both
SDKs; c2pa-rs is handed the PEM certificate, the state-machine side the DER
form of the same cert). The claim is the baseline single `c2pa.created`
action, expressed in each SDK's own definition shape, so only the container
handling and signing cost differ.

**Validation** input is each asset *as freshly signed by the state-machine
SDK*, so both readers validate byte-identical, known-good input and perform
the full hash + signature + chain work. The final trust verdict is incidental
(the test signer is untrusted), and does not change the work measured.

## Test assets

All assets are from the c2pa-rs SDK fixtures folder
(`c2pa-rs/sdk/tests/fixtures`): every `*.jpg`/`*.jpeg` and
`*.tif`/`*.tiff`/`*.dng` file at its top level — 24 JPEG and 6 TIFF/DNG.

### JPEG (24)

| Asset | Size | Asset | Size |
|---|---:|---|---:|
| `adobe-20220124-E-clm-CAICAI.jpg` | 640.9 KiB | `cloudx.jpg` | 179.6 KiB |
| `boxhash.jpg` | 170.2 KiB | `earth_apollo17.jpg` | 179.4 KiB |
| `C.jpg` | 129.4 KiB | `E-sig-CA.jpg` | 163.0 KiB |
| `CA.jpg` | 163.0 KiB | `IMG_0003.jpg` | 60.3 KiB |
| `CA_ct.jpg` | 163.0 KiB | `legacy_ingredient_hash.jpg` | 370.1 KiB |
| `CACA.jpg` | 273.2 KiB | `no_alg.jpg` | 84.5 KiB |
| `CACAE-uri-CA.jpg` | 379.1 KiB | `no_manifest.jpg` | 95.3 KiB |
| `CIE-sig-CA.jpg` | 346.2 KiB | `ocsp.jpg` | 278.9 KiB |
| `C_with_CAWG_data.jpg` | 136.4 KiB | `ocsp_with_assertion.jpg` | 585.7 KiB |
| `cloud.jpg` | 179.6 KiB | `P1000827.jpg` | 163.6 KiB |
| `prerelease.jpg` | 366.2 KiB | `thumbnail.jpg` | 60.3 KiB |
| `update_manifest.jpg` | 222.0 KiB | `XCA.jpg` | 139.4 KiB |

### TIFF / BigTIFF / DNG (6)

| Asset | Size | Notes |
|---|---:|---|
| `MultiPage.tif` | 138.1 KiB | multi-page TIFF |
| `TUSCANY.TIF` | 201.0 KiB | |
| `test.tiff` | 430.7 KiB | |
| `tiff_poc.tiff` | 37.1 KiB | adversarial proof-of-concept TIFF |
| `subfiles.dng` | 16.2 MiB | DNG with sub-IFDs |
| `Foo.dng` | 34.1 MiB | large DNG |

## Summary

Geometric mean of the per-asset ratio **c2pa-rs ÷ state-machine**, over the
assets both SDKs processed successfully. A value **> 1 means the
state-machine SDK is faster / uses less memory**.

| Workflow | Format | Time (rs/sm) | Memory (rs/sm) |
|---|---|---:|---:|
| **Sign** | JPEG (24) | 0.98× (≈ parity) | **1.73×** |
| **Sign** | TIFF/DNG (5) | **1.69×** | **9.25×** |
| **Validate** | JPEG (24) | **1.20×** | 1.11× |
| **Validate** | TIFF/DNG (5) | **1.38×** | **4.72×** |

**Key findings:**

1. **Small JPEGs — roughly at parity on time**, with the state-machine SDK
   modestly lighter on memory (it buffers less per signature).
2. **Large TIFF/DNG — the state-machine SDK is both faster and dramatically
   lighter.** It streams the asset in bounded chunks (peak heap ~0.5–1 MiB
   regardless of file size), while c2pa-rs buffers the whole file, so its
   memory scales with the asset. For `Foo.dng` (34 MiB) signing, the
   state-machine SDK holds **1.0 MiB** of peak heap against c2pa-rs's
   **98 MiB** — a ~97× difference — and finishes in about half the time.
3. `tiff_poc.tiff` (an adversarial fixture) is **refused by c2pa-rs** on both
   sign and read; the state-machine SDK processes it. It is excluded from the
   geometric means.

## Full results

Measured on an **Apple M4 Max, macOS 26.6.2**, release build, ES256, median
of 7 iterations. Memory is peak additional heap. `rs/sm` columns are the
c2pa-rs ÷ state-machine ratio (> 1 favours the state-machine SDK). Time
figures vary run-to-run by a few tenths of a millisecond on sub-millisecond
operations; memory figures are deterministic.

### Signing (ES256, file-based)

| Fmt | Asset | Size | SM time | SM mem | rs time | rs mem | time rs/sm | mem rs/sm |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| JPEG | `C.jpg` | 129.4 KiB | 0.75 ms | 98.1 KiB | 0.63 ms | 264.6 KiB | 0.83× | 2.70× |
| JPEG | `CA.jpg` | 163.0 KiB | 1.14 ms | 237.5 KiB | 0.75 ms | 331.6 KiB | 0.66× | 1.40× |
| JPEG | `CACA.jpg` | 273.2 KiB | 0.55 ms | 461.5 KiB | 0.68 ms | 552.2 KiB | 1.24× | 1.20× |
| JPEG | `CACAE-uri-CA.jpg` | 379.1 KiB | 0.62 ms | 558.0 KiB | 0.82 ms | 763.9 KiB | 1.32× | 1.37× |
| JPEG | `CA_ct.jpg` | 163.0 KiB | 0.60 ms | 237.5 KiB | 0.63 ms | 331.6 KiB | 1.05× | 1.40× |
| JPEG | `CIE-sig-CA.jpg` | 346.2 KiB | 0.61 ms | 460.2 KiB | 0.81 ms | 698.2 KiB | 1.32× | 1.52× |
| JPEG | `C_with_CAWG_data.jpg` | 136.4 KiB | 0.80 ms | 112.2 KiB | 0.72 ms | 278.5 KiB | 0.90× | 2.48× |
| JPEG | `E-sig-CA.jpg` | 163.0 KiB | 0.55 ms | 237.5 KiB | 0.77 ms | 331.6 KiB | 1.39× | 1.40× |
| JPEG | `IMG_0003.jpg` | 60.3 KiB | 0.69 ms | 68.0 KiB | 0.55 ms | 195.2 KiB | 0.80× | 2.87× |
| JPEG | `P1000827.jpg` | 163.6 KiB | 0.83 ms | 171.4 KiB | 0.84 ms | 374.4 KiB | 1.01× | 2.18× |
| JPEG | `XCA.jpg` | 139.4 KiB | 0.72 ms | 237.3 KiB | 0.59 ms | 284.0 KiB | 0.83× | 1.20× |
| JPEG | `adobe-20220124-E-clm-CAICAI.jpg` | 640.9 KiB | 0.69 ms | 1.1 MiB | 0.72 ms | 1.3 MiB | 1.04× | 1.12× |
| JPEG | `boxhash.jpg` | 170.2 KiB | 0.77 ms | 247.0 KiB | 0.62 ms | 348.6 KiB | 0.81× | 1.41× |
| JPEG | `cloud.jpg` | 179.6 KiB | 0.67 ms | 187.3 KiB | 0.64 ms | 389.2 KiB | 0.95× | 2.08× |
| JPEG | `cloudx.jpg` | 179.6 KiB | 0.97 ms | 187.3 KiB | 0.59 ms | 389.2 KiB | 0.61× | 2.08× |
| JPEG | `earth_apollo17.jpg` | 179.4 KiB | 0.59 ms | 187.2 KiB | 0.63 ms | 388.8 KiB | 1.07× | 2.08× |
| JPEG | `legacy_ingredient_hash.jpg` | 370.1 KiB | 0.62 ms | 628.1 KiB | 0.71 ms | 748.3 KiB | 1.14× | 1.19× |
| JPEG | `no_alg.jpg` | 84.5 KiB | 0.72 ms | 84.7 KiB | 0.83 ms | 183.9 KiB | 1.15× | 2.17× |
| JPEG | `no_manifest.jpg` | 95.3 KiB | 0.69 ms | 103.1 KiB | 0.56 ms | 220.6 KiB | 0.81× | 2.14× |
| JPEG | `ocsp.jpg` | 278.9 KiB | 0.54 ms | 509.7 KiB | 0.74 ms | 563.5 KiB | 1.35× | 1.11× |
| JPEG | `ocsp_with_assertion.jpg` | 585.7 KiB | 0.67 ms | 1.1 MiB | 0.59 ms | 1.2 MiB | 0.87× | 1.08× |
| JPEG | `prerelease.jpg` | 366.2 KiB | 0.74 ms | 314.9 KiB | 0.88 ms | 740.5 KiB | 1.19× | 2.35× |
| JPEG | `thumbnail.jpg` | 60.3 KiB | 0.68 ms | 68.0 KiB | 0.55 ms | 195.2 KiB | 0.80× | 2.87× |
| JPEG | `update_manifest.jpg` | 222.0 KiB | 0.70 ms | 186.2 KiB | 0.73 ms | 453.4 KiB | 1.04× | 2.43× |
| TIFF | `MultiPage.tif` | 138.1 KiB | 0.64 ms | 146.1 KiB | 1.11 ms | 421.8 KiB | 1.74× | 2.89× |
| TIFF | `TUSCANY.TIF` | 201.0 KiB | 0.75 ms | 209.1 KiB | 0.78 ms | 479.8 KiB | 1.04× | 2.29× |
| TIFF | `test.tiff` | 430.7 KiB | 0.84 ms | 438.9 KiB | 1.10 ms | 965.9 KiB | 1.31× | 2.20× |
| TIFF | `subfiles.dng` | 16.2 MiB | 9.62 ms | 1.0 MiB | 26.22 ms | 48.2 MiB | 2.72× | 47.80× |
| TIFF | `Foo.dng` | 34.1 MiB | 20.12 ms | 1.0 MiB | 43.12 ms | 98.1 MiB | 2.14× | 97.17× |
| TIFF | `tiff_poc.tiff` | 37.1 KiB | 1.85 ms | 58.9 KiB | — (refused) | — | — | — |

### Validation (of the state-machine-signed output, file-based)

Sizes here are the signed outputs (slightly different from the originals).

| Fmt | Asset | Size | SM time | SM mem | rs time | rs mem | time rs/sm | mem rs/sm |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| JPEG | `C.jpg` | 86.4 KiB | 0.23 ms | 92.9 KiB | 0.32 ms | 101.2 KiB | 1.40× | 1.09× |
| JPEG | `CA.jpg` | 50.2 KiB | 0.29 ms | 56.7 KiB | 0.26 ms | 65.0 KiB | 0.90× | 1.15× |
| JPEG | `CACA.jpg` | 48.5 KiB | 0.21 ms | 55.0 KiB | 0.27 ms | 63.3 KiB | 1.27× | 1.15× |
| JPEG | `CACAE-uri-CA.jpg` | 106.2 KiB | 0.28 ms | 112.7 KiB | 0.29 ms | 121.0 KiB | 1.04× | 1.07× |
| JPEG | `CA_ct.jpg` | 50.2 KiB | 0.23 ms | 56.7 KiB | 0.27 ms | 65.0 KiB | 1.21× | 1.15× |
| JPEG | `CIE-sig-CA.jpg` | 122.1 KiB | 0.25 ms | 128.6 KiB | 0.29 ms | 136.9 KiB | 1.19× | 1.06× |
| JPEG | `C_with_CAWG_data.jpg` | 86.3 KiB | 0.26 ms | 92.8 KiB | 0.28 ms | 101.1 KiB | 1.07× | 1.09× |
| JPEG | `E-sig-CA.jpg` | 50.2 KiB | 0.24 ms | 56.7 KiB | 0.27 ms | 65.0 KiB | 1.12× | 1.15× |
| JPEG | `IMG_0003.jpg` | 62.1 KiB | 0.22 ms | 68.5 KiB | 0.29 ms | 76.8 KiB | 1.35× | 1.12× |
| JPEG | `P1000827.jpg` | 165.4 KiB | 0.30 ms | 172.0 KiB | 0.35 ms | 180.2 KiB | 1.16× | 1.05× |
| JPEG | `XCA.jpg` | 26.7 KiB | 0.23 ms | 33.2 KiB | 0.29 ms | 40.9 KiB | 1.26× | 1.23× |
| JPEG | `adobe-20220124-E-clm-CAICAI.jpg` | 70.6 KiB | 0.23 ms | 77.1 KiB | 0.28 ms | 85.5 KiB | 1.19× | 1.11× |
| JPEG | `boxhash.jpg` | 52.7 KiB | 0.23 ms | 59.2 KiB | 0.27 ms | 67.5 KiB | 1.19× | 1.14× |
| JPEG | `cloud.jpg` | 181.4 KiB | 0.27 ms | 187.9 KiB | 0.31 ms | 196.1 KiB | 1.17× | 1.04× |
| JPEG | `cloudx.jpg` | 181.4 KiB | 0.27 ms | 187.9 KiB | 0.32 ms | 196.1 KiB | 1.18× | 1.04× |
| JPEG | `earth_apollo17.jpg` | 181.2 KiB | 0.26 ms | 187.7 KiB | 0.33 ms | 195.9 KiB | 1.25× | 1.04× |
| JPEG | `legacy_ingredient_hash.jpg` | 62.2 KiB | 0.22 ms | 68.6 KiB | 0.27 ms | 77.0 KiB | 1.22× | 1.12× |
| JPEG | `no_alg.jpg` | 78.7 KiB | 0.23 ms | 85.2 KiB | 0.28 ms | 93.5 KiB | 1.22× | 1.10× |
| JPEG | `no_manifest.jpg` | 97.1 KiB | 0.23 ms | 103.6 KiB | 0.29 ms | 111.8 KiB | 1.26× | 1.08× |
| JPEG | `ocsp.jpg` | 30.1 KiB | 0.21 ms | 36.6 KiB | 0.26 ms | 45.0 KiB | 1.26× | 1.23× |
| JPEG | `ocsp_with_assertion.jpg` | 44.8 KiB | 0.21 ms | 51.2 KiB | 0.27 ms | 59.6 KiB | 1.30× | 1.16× |
| JPEG | `prerelease.jpg` | 214.8 KiB | 0.28 ms | 222.4 KiB | 0.33 ms | 229.6 KiB | 1.18× | 1.03× |
| JPEG | `thumbnail.jpg` | 62.1 KiB | 0.22 ms | 68.5 KiB | 0.28 ms | 76.8 KiB | 1.30× | 1.12× |
| JPEG | `update_manifest.jpg` | 181.2 KiB | 0.28 ms | 187.7 KiB | 0.32 ms | 196.0 KiB | 1.15× | 1.04× |
| TIFF | `MultiPage.tif` | 139.9 KiB | 0.25 ms | 146.4 KiB | 0.49 ms | 159.7 KiB | 1.92× | 1.09× |
| TIFF | `TUSCANY.TIF` | 202.8 KiB | 0.31 ms | 210.5 KiB | 0.37 ms | 218.0 KiB | 1.20× | 1.04× |
| TIFF | `test.tiff` | 432.5 KiB | 0.38 ms | 440.3 KiB | 0.57 ms | 448.0 KiB | 1.48× | 1.02× |
| TIFF | `subfiles.dng` | 16.2 MiB | 7.46 ms | 529.8 KiB | 8.59 ms | 16.2 MiB | 1.15× | 31.34× |
| TIFF | `Foo.dng` | 34.1 MiB | 14.73 ms | 537.8 KiB | 18.96 ms | 34.1 MiB | 1.29× | 65.00× |
| TIFF | `tiff_poc.tiff` | 38.9 KiB | 1.42 ms | 51.9 KiB | — (refused) | — | — | — |

## Caveats and notes

- **Allocator overhead.** The tracking global allocator adds a small, uniform
  atomic cost to every allocation on both SDKs, so the *relative* comparisons
  are sound; absolute millisecond figures are slightly higher than an
  untracked build would show.
- **Memory metric.** Peak additional heap is the correct cross-SDK metric
  here. Whole-process RSS would not work for per-operation deltas (it is a
  monotonic high-water mark), and the OS page cache — which file I/O touches —
  is deliberately not counted.
- **Validation state.** The test signer is untrusted, so validation reports
  `Invalid`/`Valid` rather than `Trusted`; this does not change the hashing,
  signature-verification, or chain-building work the readers perform.
- **Machine variance.** The sub-millisecond JPEG timings are near the
  measurement floor; treat them as "parity" rather than reading individual
  tenths. The memory figures and the large-asset (DNG) timings are the
  robust, reproducible signal.
