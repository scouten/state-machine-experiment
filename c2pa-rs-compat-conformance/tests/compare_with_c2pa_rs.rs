//! The one-file demonstration: the same client code
//! ([`read_and_summarize`]) reads the same file through real c2pa-rs and
//! through [`contentauth_c2pa_rs_compat`], and gets the same answer.
//!
//! `C.jpg` is not a fixture built for this comparison — it is a real asset
//! signed by an actual c2pa-rs release (`make_test_images`/c2pa-rs 0.33.1),
//! already checked into `contentauth-c2pa-reader`'s own test fixtures and
//! read there for the same reason: proving the code copes with a real
//! writer's output, not just its own.

use std::path::Path;

use c2pa_rs_compat_conformance::read_and_summarize;

#[test]
fn c2pa_rs_and_the_compat_reader_agree_on_a_real_c2pa_rs_signed_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../contentauth-c2pa-reader/tests/fixtures/C.jpg");

    let via_c2pa_rs = read_and_summarize::<c2pa::Reader>(&path).expect("c2pa-rs should read C.jpg");
    let via_compat = read_and_summarize::<contentauth_c2pa_rs_compat::Reader>(&path)
        .expect("the compat reader should read C.jpg");

    assert_eq!(
        via_c2pa_rs, via_compat,
        "the same client code should see the same thing through either backend"
    );

    // Pinned so this test also documents, rather than just proves, what the
    // two backends agree on for this specific fixture: no trust anchor
    // this repository holds covers the fixture's own test signer, so both
    // land on `Valid` rather than `Trusted` — real c2pa-rs's own bundled
    // trust list doesn't cover a synthetic test certificate either.
    assert_eq!(via_compat.validation_state, "Valid");
    assert_eq!(
        via_compat.active_label.as_deref(),
        Some("contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3")
    );
    assert_eq!(via_compat.title.as_deref(), Some("C.jpg"));
    assert_eq!(via_compat.format.as_deref(), Some("image/jpeg"));
    assert_eq!(
        via_compat.instance_id.as_deref(),
        Some("xmp:iid:22704d84-c37f-4733-a207-56c4c2e67b1a")
    );
    assert_eq!(
        via_compat.claim_generator.as_deref(),
        Some("make_test_images/0.33.1 c2pa-rs/0.33.1")
    );
}
