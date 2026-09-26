// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Any octets through the GOOSE decoders: no panic, the values of an
//! accepted message are all readable, as many top-level ones as counted,
//! and what the strict decoding accepts the lenient one accepts, the same.

#![no_main]

use libfuzzer_sys::fuzz_target;
use open61850_core::data::{self, Data};
use open61850_core::goose;

/// Top-level values of a preorder sequence.
fn top_level(values: &[Data<'_>]) -> usize {
    let (mut count, mut pending) = (0usize, 0usize);
    for v in values {
        if pending == 0 {
            count += 1;
        } else {
            pending -= 1;
        }
        if let Data::Structure(n) | Data::Array(n) = v {
            pending += n;
        }
    }
    count
}

fn walk(message: &goose::Received<'_>) {
    let values: Vec<Data<'_>> = message.values().collect();
    assert_eq!(top_level(&values), message.entries);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((_, m))) = goose::decode_frame(data) {
        walk(&m);
    }
    if let Ok((_, m)) = goose::decode_payload(data) {
        walk(&m);
    }
    if let Ok(m) = goose::decode_pdu(data) {
        walk(&m);
    }
    if let Ok(strict) = goose::decode_pdu_strict(data) {
        assert_eq!(Ok(strict), goose::decode_pdu(data));
        assert_eq!(strict.num_dat_set_entries, strict.entries as u64);
    }
    if data::check_sequence(data).is_ok() {
        data::iter_sequence(data).for_each(drop);
    }
});
