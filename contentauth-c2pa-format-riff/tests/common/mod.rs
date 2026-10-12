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

//! Synthetic RIFF files and manifest stores for the integration tests.

#![allow(dead_code)]

/// The type UUID of a C2PA manifest store superbox.
const MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// A RIFF file of the given form with the given chunks, pad bytes and all.
pub fn riff(form: &[u8; 4], chunks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut body = form.to_vec();
    for (id, data) in chunks {
        body.extend_from_slice(*id);
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        if data.len() % 2 == 1 {
            body.push(0);
        }
    }
    let mut file = b"RIFF".to_vec();
    file.extend_from_slice(&(body.len() as u32).to_le_bytes());
    file.extend(body);
    file
}

/// A WAV: a PCM `fmt ` chunk and `samples` bytes of audio.
pub fn wav(samples: usize) -> Vec<u8> {
    let mut fmt = vec![1, 0, 1, 0];
    fmt.extend(8000u32.to_le_bytes());
    fmt.extend(8000u32.to_le_bytes());
    fmt.extend([1, 0, 8, 0]);
    let audio = (0..samples).map(|i| (i % 251) as u8).collect();
    riff(b"WAVE", &[(b"fmt ", fmt), (b"data", audio)])
}

/// An AVI-shaped file: nested `LIST`s, an odd-sized chunk, and an index.
pub fn avi() -> Vec<u8> {
    let mut hdrl = b"hdrl".to_vec();
    hdrl.extend_from_slice(b"avih\x04\0\0\0\0\0\0\0");
    riff(
        b"AVI ",
        &[
            (b"LIST", hdrl),
            (b"JUNK", vec![0; 7]),
            (b"LIST", [b"movi".to_vec(), vec![0xab; 4096]].concat()),
            (b"idx1", vec![1; 16]),
        ],
    )
}

/// A plausible manifest store of `len` bytes: a real superbox and
/// description-box header naming it a C2PA store, then a non-repeating
/// fill so a misplaced byte is caught.
pub fn store(len: usize) -> Vec<u8> {
    assert!(len >= 32);
    let mut store = (len as u32).to_be_bytes().to_vec();
    store.extend_from_slice(b"jumb");
    store.extend_from_slice(&[0, 0, 0, 0x1e]);
    store.extend_from_slice(b"jumd");
    store.extend_from_slice(&MANIFEST_STORE_UUID);
    store.extend((32..len).map(|i| (i % 251) as u8));
    store
}
