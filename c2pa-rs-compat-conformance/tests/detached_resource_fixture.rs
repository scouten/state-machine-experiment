//! Keep the stored Node differential oracle grounded in the real SDK.
use std::io::Cursor;

const ASSET: &[u8] =
    include_bytes!("../../c2pa-js-state-machine/browser/fixtures/detached-data-v2.jpg");
const MANIFEST: &[u8] =
    include_bytes!("../../c2pa-js-state-machine/browser/fixtures/detached-data-v2.c2pa");
const GOLDEN: &str =
    include_str!("../../c2pa-js-state-machine/browser/fixtures/detached-data-v2-report.json");

#[test]
fn stored_detached_resource_oracle_matches_real_c2pa_rs() -> Result<(), Box<dyn std::error::Error>>
{
    // The generator records a trusted report; disable only trust here and
    // compare the manifest projections, then verify binding failures separately.
    let context = c2pa::Context::new()
        .with_settings(r#"{"verify":{"verify_trust":false,"ocsp_fetch":false}}"#)?;
    let reader = c2pa::Reader::from_context(context).with_manifest_data_and_stream(
        MANIFEST,
        "image/jpeg",
        Cursor::new(ASSET),
    )?;
    let actual: serde_json::Value = serde_json::from_str(&reader.json())?;
    let golden: serde_json::Value = serde_json::from_str(GOLDEN)?;
    assert_eq!(actual["manifests"], golden["manifests"]);
    assert_eq!(actual["active_manifest"], golden["active_manifest"]);
    assert!(!reader.is_embedded());
    let bare = c2pa::Reader::from_context(c2pa::Context::new())
        .with_stream("image/jpeg", Cursor::new(ASSET));
    assert!(matches!(bare, Err(c2pa::Error::JumbfNotFound)));
    let mut changed = ASSET.to_vec();
    changed.push(0);
    let reader = c2pa::Reader::from_context(c2pa::Context::new()).with_manifest_data_and_stream(
        MANIFEST,
        "image/jpeg",
        Cursor::new(changed),
    )?;
    assert_eq!(reader.validation_state(), c2pa::ValidationState::Invalid);
    Ok(())
}
