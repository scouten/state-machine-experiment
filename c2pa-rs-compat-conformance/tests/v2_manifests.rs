//! A manifest signed by real c2pa-rs as a **v2** claim (its default) is
//! read by this workspace's reader without complaint — the interop check
//! for the v2 claim shape, which differs from v1 in ways (a single-map
//! `claim_generator_info`, no `dc:format`, required fields) a reader only
//! written against v1 bytes would get wrong.

use std::{io::Cursor, path::Path};

use c2pa::{Builder, SigningAlg};
use contentauth_c2pa_rs_compat::{ClaimVersion, Context, Reader, ValidationState};

const SIGNER_CERT_DER: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");
const SIGNER_KEY_PEM: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

/// A minimal, well-formed JPEG nobody has ever signed.
fn unsigned_jpeg() -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8]; // SOI

    let jfif: &[u8] = b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0";
    bytes.extend_from_slice(&[0xff, 0xe0]); // APP0
    bytes.extend_from_slice(&(jfif.len() as u16 + 2).to_be_bytes());
    bytes.extend_from_slice(jfif);

    let dqt = [0u8; 65];
    bytes.extend_from_slice(&[0xff, 0xdb]); // DQT
    bytes.extend_from_slice(&(dqt.len() as u16 + 2).to_be_bytes());
    bytes.extend_from_slice(&dqt);

    let sos = [1u8, 1, 0, 0, 0x3f, 0];
    bytes.extend_from_slice(&[0xff, 0xda]); // SOS
    bytes.extend_from_slice(&(sos.len() as u16 + 2).to_be_bytes());
    bytes.extend_from_slice(&sos);

    bytes.extend_from_slice(&[0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56]); // scan data
    bytes.extend_from_slice(&[0xff, 0xd9]); // EOI
    bytes
}

/// PEM-encodes one DER certificate (c2pa-rs's signer constructors take PEM).
fn cert_pem(der: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem.into_bytes()
}

fn sign_with_c2pa_rs(version: Option<u8>) -> Vec<u8> {
    let signer = c2pa::create_signer::from_keys(
        &cert_pem(SIGNER_CERT_DER),
        SIGNER_KEY_PEM,
        SigningAlg::Es256,
        None,
    )
    .expect("the test signer is usable");

    // The test signer chains to no trust anchor c2pa-rs holds, which its
    // own verify-after-sign pass would otherwise reject.
    let context = c2pa::Context::new()
        .with_settings(r#"{ "verify": { "verify_after_sign": false } }"#)
        .expect("valid settings");
    let mut builder = Builder::from_context(context)
        .with_definition(definition(version))
        .expect("a valid definition");
    let mut out = Cursor::new(Vec::new());
    builder
        .sign(
            &*signer,
            "image/jpeg",
            &mut Cursor::new(unsigned_jpeg()),
            &mut out,
        )
        .expect("c2pa-rs signs the JPEG");
    out.into_inner()
}

fn definition(version: Option<u8>) -> String {
    let version = version.map_or(String::new(), |v| format!(r#""claim_version": {v},"#));
    format!(
        r#"{{ {version}
            "claim_generator_info": [{{ "name": "conformance", "version": "1.0" }}],
            "title": "v2.jpg",
            "assertions": [{{
                "label": "c2pa.actions.v2",
                "data": {{ "actions": [{{
                    "action": "c2pa.created",
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                }}] }}
            }}] }}"#
    )
}

fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, bytes).expect("temp file is writable");
    path
}

#[test]
fn a_manifest_c2pa_rs_signed_as_v2_reads_back_as_a_v2_claim_without_failures() {
    let path = write_temp("c2pa_rs_v2.jpg", &sign_with_c2pa_rs(None));

    let reader = Reader::from_context(Context::new())
        .with_file(&path)
        .expect("the compat reader reads a c2pa-rs-signed v2 manifest");

    // The same file through real c2pa-rs: it agrees this is a v2 claim.
    let real = c2pa::Reader::from_context(c2pa::Context::new())
        .with_file(&path)
        .expect("c2pa-rs reads its own output");
    assert_eq!(
        real.active_manifest().and_then(|m| m.claim_version()),
        Some(2)
    );

    let active = reader.active_manifest().expect("an active manifest");
    assert_eq!(active.claim_version(), ClaimVersion::V2);
    assert_eq!(active.format(), None, "a v2 claim has no dc:format");

    let info = active.claim_generator_info();
    assert_eq!(info.len(), 1, "a v2 generator info is one map");
    assert!(info[0].name.is_some());

    // Nothing in the report is a failure: in particular, no `claim.malformed`
    // for a claim real c2pa-rs wrote. (No trust anchor is configured, so
    // the state is `Valid`, not `Trusted`.)
    let json = reader.json();
    assert!(!json.contains("claim.malformed"), "{json}");
    assert!(!json.contains("mismatch"), "{json}");
    assert_eq!(reader.validation_state(), ValidationState::Valid, "{json}");
}

#[test]
fn the_same_signer_with_a_v1_claim_still_reads() {
    let path = write_temp("c2pa_rs_v1.jpg", &sign_with_c2pa_rs(Some(1)));

    let reader = Reader::from_context(Context::new())
        .with_file(&path)
        .expect("the compat reader reads a c2pa-rs-signed v1 manifest");

    let active = reader.active_manifest().expect("an active manifest");
    assert_eq!(active.claim_version(), ClaimVersion::V1);
    assert_eq!(reader.validation_state(), ValidationState::Valid);
}

/// Signs with the repository's test key. It protects nothing.
struct WorkspaceSigner;

impl contentauth_c2pa_rs_compat_sign::Signer for WorkspaceSigner {
    fn alg(&self) -> contentauth_c2pa_rs_compat_sign::SigningAlg {
        contentauth_c2pa_rs_compat_sign::SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![SIGNER_CERT_DER.to_vec()]
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, contentauth_c2pa_rs_compat_sign::HostError> {
        c2pa_raw_crypto::signer_from_private_key(SIGNER_KEY_PEM, c2pa_raw_crypto::SigningAlg::Es256)
            .and_then(|signer| signer.sign(data))
            .map_err(|err| contentauth_c2pa_rs_compat_sign::HostError::new(err.to_string()))
    }
}

/// The other direction: a manifest this workspace's *builder* writes is
/// read by real c2pa-rs as a v2 claim, with a valid signature and a hard
/// binding that matches — so a write-side mistake that this workspace's own
/// reader happened to forgive would still be caught here.
#[test]
fn a_manifest_the_workspace_builder_wrote_is_a_valid_v2_claim_to_c2pa_rs() {
    let mut signed = Cursor::new(Vec::new());
    contentauth_c2pa_rs_compat_sign::Builder::from_json(
        contentauth_c2pa_sign_baseline::BASELINE_DEFINITION,
    )
    .expect("the baseline definition is valid")
    .sign(
        &WorkspaceSigner,
        "image/jpeg",
        Cursor::new(unsigned_jpeg()),
        &mut signed,
    )
    .expect("the workspace builder signs the JPEG");
    let path = write_temp("workspace_built_v2.jpg", &signed.into_inner());

    let reader = c2pa::Reader::from_context(c2pa::Context::new())
        .with_file(&path)
        .expect("c2pa-rs reads the workspace-built manifest");

    let active = reader.active_manifest().expect("an active manifest");
    assert_eq!(active.claim_version(), Some(2), "{}", reader.json());
    assert_eq!(active.title(), Some("baseline.jpg"));

    let results = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .expect("c2pa-rs validated the active manifest");
    let failures: Vec<&str> = results.failure().iter().map(|s| s.code()).collect();
    let successes: Vec<&str> = results.success().iter().map(|s| s.code()).collect();
    // The only complaint is that the test signer chains to no trust
    // anchor c2pa-rs holds; everything about the claim, its hashes, its
    // binding and its signature is sound.
    assert_eq!(failures, ["signingCredential.untrusted"], "{failures:?}");
    assert!(
        successes.contains(&"claimSignature.validated"),
        "{successes:?}"
    );
    assert!(
        successes.contains(&"assertion.dataHash.match"),
        "{successes:?}"
    );
    assert!(
        successes.contains(&"assertion.hashedURI.match"),
        "{successes:?}"
    );
}

/// A definition that opens a source (the parent) and places a logo, in
/// the JSON both c2pa-rs's `Builder` and this workspace's `Definition`
/// accept. The `ingredients` have no manifest of their own, which is all
/// this workspace's builder writes so far.
const INGREDIENTS_DEFINITION: &str = r#"{
    "title": "edited.jpg",
    "instance_id": "xmp:iid:00000000-0000-4000-8000-000000000001",
    "label": "urn:uuid:00000000-0000-4000-8000-000000000002",
    "claim_generator_info": [{ "name": "conformance", "version": "1.0" }],
    "ingredients": [
        { "relationship": "parentOf", "title": "source.jpg", "format": "image/jpeg",
          "instance_id": "xmp:iid:source", "label": "source" },
        { "relationship": "componentOf", "title": "logo.png", "format": "image/png",
          "instance_id": "xmp:iid:logo" }
    ],
    "assertions": [{
        "label": "c2pa.actions.v2",
        "data": { "actions": [
            { "action": "c2pa.opened", "parameters": { "ingredientIds": ["source"] } },
            { "action": "c2pa.cropped" }
        ] }
    }]
}"#;

/// Ingredients this workspace's builder writes — the assertions, and the
/// `c2pa.opened`/`c2pa.placed` actions naming them by hashed URI — are
/// read by real c2pa-rs as the same two ingredients, with no failure but
/// the test signer's untrusted chain.
#[test]
fn ingredients_the_workspace_builder_wrote_are_ingredients_to_c2pa_rs() {
    let mut signed = Cursor::new(Vec::new());
    contentauth_c2pa_rs_compat_sign::Builder::from_json(INGREDIENTS_DEFINITION)
        .expect("a valid definition")
        .sign(
            &WorkspaceSigner,
            "image/jpeg",
            Cursor::new(unsigned_jpeg()),
            &mut signed,
        )
        .expect("the workspace builder signs the JPEG");
    let path = write_temp("workspace_built_ingredients.jpg", &signed.into_inner());

    let reader = c2pa::Reader::from_context(c2pa::Context::new())
        .with_file(&path)
        .expect("c2pa-rs reads the workspace-built manifest");
    let active = reader.active_manifest().expect("an active manifest");

    let ingredients = active.ingredients();
    assert_eq!(ingredients.len(), 2, "{}", reader.json());
    let parent = ingredients
        .iter()
        .find(|i| i.is_parent())
        .expect("one ingredient is the parent");
    assert_eq!(parent.title(), Some("source.jpg"));
    assert_eq!(parent.instance_id(), "xmp:iid:source");
    assert!(ingredients
        .iter()
        .any(|i| i.title() == Some("logo.png") && !i.is_parent()));

    // The actions c2pa-rs finds are the ones that were written, the
    // opening one first and the placement the builder added.
    let json: serde_json::Value = serde_json::from_str(&reader.json()).expect("json");
    let actions = json["manifests"][reader.active_label().expect("label")]["assertions"]
        .as_array()
        .expect("assertions")
        .iter()
        .find(|a| {
            a["label"]
                .as_str()
                .is_some_and(|l| l.starts_with("c2pa.actions"))
        })
        .expect("an actions assertion")["data"]["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .map(|a| a["action"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(actions, ["c2pa.opened", "c2pa.cropped", "c2pa.placed"]);

    let results = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .expect("c2pa-rs validated the active manifest");
    let failures: Vec<&str> = results.failure().iter().map(|s| s.code()).collect();
    assert_eq!(failures, ["signingCredential.untrusted"], "{failures:?}");
}

/// The other direction: a parent and a component that c2pa-rs wrote read
/// back in this workspace's reader as ingredients that pass every check it
/// makes — including that the `c2pa.opened` and `c2pa.placed` actions
/// c2pa-rs wrote name the right ingredient assertions, by hash.
#[test]
fn ingredients_c2pa_rs_wrote_pass_the_workspace_readers_checks() {
    let signer = c2pa::create_signer::from_keys(
        &cert_pem(SIGNER_CERT_DER),
        SIGNER_KEY_PEM,
        SigningAlg::Es256,
        None,
    )
    .expect("the test signer is usable");
    let context = c2pa::Context::new()
        .with_settings(r#"{ "verify": { "verify_after_sign": false } }"#)
        .expect("valid settings");

    // c2pa-rs's own spelling: no `instance_id`/`label` of the manifest, and
    // it names the opening ingredient by `ingredientIds` just the same.
    let definition = INGREDIENTS_DEFINITION
        .replace(
            r#""instance_id": "xmp:iid:00000000-0000-4000-8000-000000000001",
    "label": "urn:uuid:00000000-0000-4000-8000-000000000002","#,
            "",
        )
        .replace(
            r#""title": "edited.jpg","#,
            r#""title": "edited.jpg", "claim_version": 2,"#,
        );
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(definition)
        .expect("a valid definition");
    let mut out = Cursor::new(Vec::new());
    builder
        .sign(
            &*signer,
            "image/jpeg",
            &mut Cursor::new(unsigned_jpeg()),
            &mut out,
        )
        .expect("c2pa-rs signs the JPEG");
    let path = write_temp("c2pa_rs_ingredients.jpg", &out.into_inner());

    let reader = Reader::from_context(Context::new())
        .with_file(&path)
        .expect("the compat reader reads a c2pa-rs-signed manifest with ingredients");

    let statuses = reader.validation_status().unwrap_or_default();
    for status in &statuses {
        let code = status.code();
        for bad in ["ingredient", "Mismatch", "malformed", "multipleParents"] {
            assert!(
                !code.contains(bad) || code == "ingredient.unknownProvenance",
                "{code}: {:?}",
                status.explanation()
            );
        }
    }
    assert_eq!(
        statuses
            .iter()
            .filter(|s| s.code() == "ingredient.unknownProvenance")
            .count(),
        2
    );
}
