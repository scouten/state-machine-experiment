//! Regenerate browser/Node embedded-resource fixtures with real c2pa-rs.
//!
//! Arguments: test signer certificate (PEM), output fixture directory.
use std::{io::Cursor, path::PathBuf};

use contentauth_c2pa_sign_baseline::fixtures::{SOURCE_JPEG, TEST_SIGNER_KEY_PEM};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let certificate = args.next().ok_or("missing test signer PEM path")?;
    let output = PathBuf::from(args.next().ok_or("missing output directory")?);
    if args.next().is_some() {
        return Err("expected test signer PEM path and output directory".into());
    }
    let signer = c2pa::create_signer::from_keys(
        &std::fs::read(&certificate)?,
        TEST_SIGNER_KEY_PEM,
        c2pa::SigningAlg::Es256,
        None,
    )?;
    std::fs::create_dir_all(&output)?;
    for (name, version) in [
        ("generator-icons", 1),
        ("generator-icons", 2),
        ("ingredient-thumbnails", 1),
        ("ingredient-thumbnails", 2),
        ("ingredient-data", 1),
        ("ingredient-data", 2),
        ("detached-data", 2),
    ] {
        let context =
            c2pa::Context::new().with_settings(r#"{"verify":{"verify_after_sign":false}}"#)?;
        let generator_icon = if name == "generator-icons" {
            r#","icon":{"format":"image/svg+xml","identifier":"generator-icon.svg"}"#
        } else {
            ""
        };
        let ingredients = if name == "ingredient-thumbnails" {
            r#","ingredients":[
              {"title":"Source image","format":"image/jpeg","instance_id":"xmp:iid:thumbnail-source",
               "relationship":"componentOf","thumbnail":{"format":"image/svg+xml","identifier":"generator-icon.svg"}},
              {"title":"Second image","format":"image/jpeg","instance_id":"xmp:iid:second-source",
               "relationship":"inputTo","thumbnail":{"format":"image/svg+xml","identifier":"generator-icon.svg"}}
            ]"#
        } else if name == "ingredient-data" && version == 1 {
            r#","ingredients":[
              {"title":"Source dataset","format":"application/json","instance_id":"xmp:iid:data-source",
               "relationship":"componentOf","data":{"format":"application/json","identifier":"ingredient-data.json"}},
              {"title":"Second dataset","format":"application/json","instance_id":"xmp:iid:second-data",
               "relationship":"inputTo","data":{"format":"application/json","identifier":"ingredient-data.json"}}
            ]"#
        } else if matches!(name, "ingredient-data" | "detached-data") {
            r#","ingredients":[
              {"title":"Source dataset","format":"application/json","instance_id":"xmp:iid:data-source",
               "relationship":"componentOf","data":{"format":"application/json","identifier":"ingredient-data.json"},
               "thumbnail":{"format":"image/svg+xml","identifier":"generator-icon.svg"}},
              {"title":"Second dataset","format":"application/json","instance_id":"xmp:iid:second-data",
               "relationship":"inputTo","data":{"format":"application/json","identifier":"ingredient-data.json"}}
            ]"#
        } else {
            ""
        };
        let definition = format!(
            r#"{{
              "claim_version":{version},
              "claim_generator_info":[{{
                "name":"M3 resource fixture","version":"1.0"{generator_icon}
              }}],
              "title":"generator-icons.jpg",
              "assertions":[{{"label":"c2pa.actions.v2","data":{{"actions":[{{
                "action":"c2pa.created",
                "digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
              }}]}}}}]
              {ingredients}
            }}"#
        );
        let mut builder = c2pa::Builder::from_context(context).with_definition(definition)?;
        builder.add_resource(
            "generator-icon.svg",
            Cursor::new(include_bytes!(
                "../../c2pa-js-state-machine/browser/fixtures/generator-icon.svg"
            )),
        )?;
        if matches!(name, "ingredient-data" | "detached-data") {
            builder.add_resource(
                "ingredient-data.json",
                Cursor::new(include_bytes!(
                    "../../c2pa-js-state-machine/browser/fixtures/ingredient-data.json"
                )),
            )?;
        }
        builder.set_no_embed(name == "detached-data");
        let mut asset = Cursor::new(Vec::new());
        let manifest = builder.sign(
            &*signer,
            "image/jpeg",
            &mut Cursor::new(SOURCE_JPEG),
            &mut asset,
        )?;
        let asset = asset.into_inner();
        std::fs::write(output.join(format!("{name}-v{version}.jpg")), &asset)?;
        if name == "detached-data" {
            std::fs::write(output.join("detached-data-v2.c2pa"), &manifest)?;
            let context = c2pa::Context::new().with_settings(
                serde_json::json!({
                    "trust": { "trust_anchors": std::fs::read_to_string(&certificate)? },
                    "verify": { "verify_trust": true, "ocsp_fetch": false }
                })
                .to_string(),
            )?;
            let reader = c2pa::Reader::from_context(context).with_manifest_data_and_stream(
                &manifest,
                "image/jpeg",
                Cursor::new(&asset),
            )?;
            if reader.validation_state() != c2pa::ValidationState::Trusted || reader.is_embedded() {
                return Err("detached fixture must validate as Trusted and non-embedded".into());
            }
            std::fs::write(output.join("detached-data-v2-report.json"), reader.json())?;
            let bare = c2pa::Reader::from_context(c2pa::Context::new())
                .with_stream("image/jpeg", Cursor::new(&asset));
            if !matches!(bare, Err(c2pa::Error::JumbfNotFound)) {
                return Err("detached fixture asset must have no embedded store".into());
            }
        }
    }
    Ok(())
}
