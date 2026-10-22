// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

//! The manifest and exclusions a finished build reports.
use super::*;

#[test]
fn c_api_short_form_timestamp_token_is_embedded_without_its_response_envelope() {
    let timestamp = vec![0x30, 10, 0x30, 3, 2, 1, 0, 0x30, 3, 2, 1, 42];
    let mut b = Build::new(&timestamp_definition());
    let mut h = Host {
        timestamp: timestamp.clone(),
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = h.drive(&mut b).unwrap();
    assert_eq!(h.seen[4], 1);
    let v = report.view();
    let m = unsafe { v.manifest.bytes().unwrap() };
    assert!(!m.is_empty());
    assert!(m
        .windows(timestamp[7..].len())
        .any(|w| w == &timestamp[7..]));
    assert!(!m.windows(timestamp.len()).any(|w| w == timestamp));
}
#[test]
fn c_api_returned_manifest_is_embedded_and_every_exclusion_is_nonempty_and_in_bounds() {
    let mut b = Build::new(BASELINE_DEFINITION);
    let mut h = Host {
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = h.drive(&mut b).unwrap();
    let v = report.view();
    let m = unsafe { v.manifest.bytes().unwrap() };
    assert!(h.output.windows(m.len()).any(|w| w == m));
    let ex = unsafe { std::slice::from_raw_parts(v.exclusions, v.exclusion_count) };
    assert_eq!(ex.len(), 1);
    assert!(ex.iter().all(|r| r.len > 0
        && r.start
            .checked_add(r.len)
            .is_some_and(|end| end <= h.output.len() as u64)));
}
