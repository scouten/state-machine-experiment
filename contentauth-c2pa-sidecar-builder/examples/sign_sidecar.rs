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

//! Signs a file with a sidecar manifest — the use case of Gavin Peacock's
//! `c2pa-sign-sample` (c2pa-core), as a *host* for `SidecarSession`.
//!
//! ```sh
//! cargo run -p contentauth-c2pa-sidecar-builder --example sign_sidecar -- photo.jpg
//! ```
//!
//! writes `photo.c2pa` (the sidecar) and `photo.ca.pem` (the ephemeral CA).
//! The CA is generated fresh on every run and anchored to nothing, so the
//! result is not trusted by any verifier by default; tell one to trust the
//! `.ca.pem` explicitly, for example
//! `c2patool trust --trust_anchors photo.ca.pem`.
//!
//! Everything this program does that a sans-I/O session cannot — open the
//! file, read ranges of it, draw random bytes, read the clock, hold the
//! signing key, write the output — is here, and nothing else is.

use std::{
    env,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use contentauth_c2pa_assertion_actions::{Action, Actions, DIGITAL_SOURCE_TYPE_EMPTY};
use contentauth_c2pa_claim::GeneratorInfo;
use contentauth_c2pa_ephemeral_cert::{generate, Params};
use contentauth_c2pa_sidecar_builder::{
    Session, SidecarReply, SidecarRequest, SidecarSession, SidecarSettings, Step,
};

fn random_hex(bytes: usize) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| format!("no entropy: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(&path)?;
    let len = file.metadata()?.len();

    // Entropy and the clock: the host's.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let chain = generate(
        &Params::new("contentauth-sidecar-example.local", now),
        &mut |buf: &mut [u8]| {
            // A failure here would mean no entropy at all; refusing to
            // continue with a predictable key matters more than a message.
            getrandom::fill(buf).unwrap_or_else(|_| std::process::abort());
        },
    )?;

    let actions = Actions::new()
        .with(Action::created(DIGITAL_SOURCE_TYPE_EMPTY))
        .encode()?;

    let manifest_label = format!("urn:uuid:{}", random_hex(16)?);
    let mut session = SidecarSession::new(SidecarSettings {
        manifest_label,
        // TODO: should be the asset's xmpMM:InstanceID when it has XMP.
        instance_id: format!("xmp:iid:{}", random_hex(16)?),
        title: path.file_name().map(|n| n.to_string_lossy().into_owned()),
        generator: GeneratorInfo::new(
            "contentauth-c2pa-sidecar-builder example",
            Some(env!("CARGO_PKG_VERSION").into()),
        ),
        signing_alg: chain.alg(),
        certificates: chain.x5chain(),
        assertions: vec![actions],
    });

    let report = loop {
        if session.advance()? == Step::Complete {
            break session.finish()?;
        }
        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                SidecarRequest::AssetLength { .. } => SidecarReply::AssetLength(len),
                SidecarRequest::AssetBytes { range, .. } => {
                    file.seek(SeekFrom::Start(range.start))?;
                    let mut bytes = vec![0u8; range.len as usize];
                    file.read_exact(&mut bytes)?;
                    SidecarReply::AssetBytes(bytes)
                }
                SidecarRequest::Sign { data, .. } => SidecarReply::Signature(chain.sign(&data)),
                other => return Err(format!("unexpected request {other:?}").into()),
            };
            session.fulfill(request.id, reply)?;
        }
    };

    let sidecar = path.with_extension("c2pa");
    let ca_pem = path.with_extension("ca.pem");
    std::fs::write(&sidecar, &report.manifest_store)?;
    std::fs::write(&ca_pem, &chain.ca_pem)?;

    println!(
        "wrote {} ({} bytes)",
        sidecar.display(),
        report.manifest_store.len()
    );
    println!(
        "wrote {} -- not a trusted CA; to validate with c2patool, run:\n  c2patool trust --trust_anchors {}",
        ca_pem.display(),
        ca_pem.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: sign_sidecar <path-to-file>");
        return ExitCode::FAILURE;
    };
    match run(PathBuf::from(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
