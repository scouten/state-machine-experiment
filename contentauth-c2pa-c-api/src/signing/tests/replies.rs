// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! Reply validation and terminal failure of a build.
use super::*;

#[test]
fn c_api_unknown_build_ids_are_rejected_for_every_reply_kind() {
    let mut b = Build::new(BASELINE_DEFINITION);
    for kind in 0..=5 {
        assert_eq!(
            b.fulfill(C2paSmBuildReply {
                kind,
                id: u64::MAX,
                data: C2paSmBuffer::borrowed(b"host reply"),
                ..Default::default()
            })
            .unwrap_err()
            .0,
            1
        );
    }
    assert!(Host::default().drive(&mut b).unwrap().view().manifest.len > 0);
}
#[test]
fn c_api_malformed_payload_matrix_preserves_the_pending_build_request() {
    let mut b = Build::new(BASELINE_DEFINITION);
    assert_eq!(b.advance().unwrap(), (false, 1));
    let r = b.request(0).unwrap();
    for kind in [0, 3, 4, 5] {
        for data in [
            C2paSmBuffer {
                data: ptr::null(),
                len: 1,
            },
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: usize::MAX,
            },
        ] {
            assert_eq!(
                b.fulfill(C2paSmBuildReply {
                    kind,
                    id: r.id,
                    data,
                    ..Default::default()
                })
                .unwrap_err()
                .0,
                1
            );
        }
    }
    assert_eq!(b.advance().unwrap(), (false, 0));
    b.fulfill(C2paSmBuildReply {
        kind: 1,
        id: r.id,
        value: SOURCE_JPEG.len() as u64,
        ..Default::default()
    })
    .unwrap();
    assert!(Host::default().drive(&mut b).unwrap().view().manifest.len > 0);
}
#[test]
fn c_api_failed_build_remains_terminal_and_finish_returns_no_report() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    b.fulfill(C2paSmBuildReply {
        kind: 5,
        id: r.id,
        data: C2paSmBuffer::borrowed(b"cancelled"),
        ..Default::default()
    })
    .unwrap();
    for _ in 0..2 {
        assert_eq!(b.advance().unwrap_err().0, 6)
    }
    assert_eq!(b.finish().unwrap_err().0, 1);
    assert!(b.0.is_null());
}
#[test]
fn empty_copying_read_reply_is_accepted_then_rejected_by_engine_length_validation() {
    let b = Build::new(BASELINE_DEFINITION);
    let r = b.first_read();
    assert!(r.len > 0);
    b.fulfill(C2paSmBuildReply {
        kind: 0,
        id: r.id,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(b.advance().unwrap_err().0, 6);
}
