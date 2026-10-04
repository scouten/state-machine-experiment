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

//! The registry's detection, and the type-erased handler held to the same
//! contract as the concrete one.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_format::{
    test_util::{conformance, MemoryHost, STREAM},
    EmbedPlan, FormatDescriptor, FormatError, FormatHandler, ManifestLocation, Patch, Signature,
    StreamId,
};
use contentauth_c2pa_format_registry::{AnyFormat, BoxedOp, DynFormatHandler, Registry};
use contentauth_c2pa_format_tiff::TiffFormat;

const JPEG: &[u8] = b"\xff\xd8\xff\xe0\x00\x10JFIF\0\x01\x02\0\0\x01\0\x01\0\0\xff\xd9";

/// One IFD, one entry, in each of the four flavors.
const TIFFS: [&[u8]; 2] = [
    b"II\x2a\0\x08\0\0\0\x01\0\0\x01\x03\0\x01\0\0\0\x01\0\0\0\0\0\0\0",
    b"MM\0\x2a\0\0\0\x08\0\x01\x01\0\0\x03\0\0\0\x01\0\x01\0\0\0\0\0\0",
];

fn name_of(format: Option<&AnyFormat>) -> Option<&'static str> {
    format.map(|f| f.descriptor().name)
}

#[test]
fn content_names_the_format() {
    let registry = Registry::standard();

    assert_eq!(name_of(registry.detect(JPEG)), Some("jpeg"));
    for tiff in TIFFS {
        assert_eq!(name_of(registry.detect(tiff)), Some("tiff"));
    }
    assert_eq!(
        name_of(registry.detect(b"MM\0\x2b\0\x08\0\0")),
        Some("tiff"),
        "BigTIFF"
    );
    assert_eq!(
        name_of(registry.detect(b"II\x2b\0\x08\0\0\0")),
        Some("tiff"),
        "BigTIFF"
    );

    assert_eq!(name_of(registry.detect(b"\x89PNG\r\n\x1a\n")), None);
    assert_eq!(name_of(registry.detect(b"")), None);
    assert_eq!(name_of(registry.detect(b"II")), None);
}

#[test]
fn one_read_of_the_window_is_enough_to_detect_anything() {
    let registry = Registry::standard();
    assert_eq!(registry.window(), 4);

    for asset in [JPEG, TIFFS[0], TIFFS[1]] {
        let header = &asset[..registry.window() as usize];
        assert_eq!(
            name_of(registry.detect(header)),
            name_of(registry.detect(asset))
        );
    }
    assert_eq!(Registry::new().window(), 0);
}

#[test]
fn hints_name_the_format_without_reading() {
    let registry = Registry::standard();

    for ext in ["jpg", "JPEG", ".jpg"] {
        assert_eq!(name_of(registry.by_extension(ext)), Some("jpeg"), "{ext}");
    }
    for ext in ["tif", "TIFF", "dng"] {
        assert_eq!(name_of(registry.by_extension(ext)), Some("tiff"), "{ext}");
    }
    assert_eq!(name_of(registry.by_extension("png")), None);

    assert_eq!(name_of(registry.by_mime("image/jpeg")), Some("jpeg"));
    assert_eq!(name_of(registry.by_mime("IMAGE/TIFF")), Some("tiff"));
    assert_eq!(name_of(registry.by_mime("image/x-adobe-dng")), Some("tiff"));
    assert_eq!(name_of(registry.by_mime("image/png")), None);
}

#[test]
fn lists_what_it_can_handle() {
    let registry = Registry::standard();
    assert_eq!(
        registry.extensions().collect::<Vec<_>>(),
        ["jpg", "jpeg", "tif", "tiff", "dng"]
    );
    assert_eq!(registry.formats().len(), 2);
}

#[test]
fn a_type_erased_handler_passes_the_conformance_suite_too() {
    let any = AnyFormat::new(TiffFormat);

    let unsigned = TIFFS[0];
    conformance::run_all(&any, unsigned, &[7; 300], &[9; 5000]);

    // And it makes the same plan as the concrete handler.
    let concrete = MemoryHost::of(unsigned)
        .run(TiffFormat.plan_embed(STREAM, 300))
        .unwrap();
    let erased = MemoryHost::of(unsigned)
        .run(any.plan_embed(STREAM, 300))
        .unwrap();
    assert_eq!(concrete, erased);
}

/// A handler that is not what the registry was built with, added at run
/// time: TIFF's logic under a different name and signature — the shape an
/// adapter over a handler written elsewhere would take, implementing
/// [`DynFormatHandler`] directly instead of the Rust-only trait.
struct Renamed;

const RENAMED: FormatDescriptor = FormatDescriptor::new(
    "renamed",
    &["application/x-renamed"],
    &["rnm"],
    &[Signature::new(0, b"RNM!")],
);

impl DynFormatHandler for Renamed {
    fn descriptor(&self) -> &FormatDescriptor {
        &RENAMED
    }

    fn locate(&self, stream: StreamId) -> BoxedOp<ManifestLocation> {
        BoxedOp::new(FormatHandler::locate(&TiffFormat, stream))
    }

    fn plan_embed(&self, stream: StreamId, len: u64) -> BoxedOp<EmbedPlan> {
        BoxedOp::new(FormatHandler::plan_embed(&TiffFormat, stream, len))
    }

    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
        TiffFormat.commit(plan, manifest)
    }
}

#[test]
fn a_format_registered_at_run_time_is_found_like_any_other() {
    let mut registry = Registry::standard();
    registry.register_any(AnyFormat::from_dyn(Renamed));

    assert_eq!(name_of(registry.detect(b"RNM!....")), Some("renamed"));
    assert_eq!(name_of(registry.by_extension("rnm")), Some("renamed"));
    assert_eq!(registry.window(), 4);

    // It is driven exactly as a built-in is.
    let renamed = registry.by_mime("application/x-renamed").unwrap();
    conformance::run_all(renamed, TIFFS[0], &[1; 64], &[2; 128]);
}

#[test]
fn earlier_registrations_win() {
    let registry = Registry::new()
        .with(AnyFormat::from_dyn(Renamed))
        .with(AnyFormat::new(TiffFormat))
        .with(AnyFormat::from_dyn(Renamed));
    assert_eq!(name_of(registry.by_extension("tif")), Some("tiff"));
    assert_eq!(registry.formats().len(), 3);
}

#[test]
fn an_any_format_is_a_format_handler_that_names_itself() {
    let any = AnyFormat::new(TiffFormat);

    assert_eq!(FormatHandler::descriptor(&any).name, "tiff");
    assert_eq!(format!("{any:?}"), "AnyFormat(\"tiff\")");
    assert!(format!("{:?}", Registry::standard()).contains("jpeg"));
}

#[test]
fn lists_the_media_types_it_can_handle() {
    assert_eq!(
        Registry::standard().mime_types().collect::<Vec<_>>(),
        ["image/jpeg", "image/tiff", "image/dng", "image/x-adobe-dng"]
    );
}
