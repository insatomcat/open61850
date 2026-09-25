// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Any octets through the SV decoder: no panic, and an accepted PDU yields
//! as many ASDUs as it declares, each sample buffer readable.

#![no_main]

use libfuzzer_sys::fuzz_target;
use open61850_core::sv;

fn walk(pdu: &sv::SvPdu<'_>) {
    assert_eq!(pdu.asdus().count(), pdu.len());
    for asdu in pdu.asdus() {
        if let Ok(samples) = sv::int32_samples(asdu.sample) {
            assert_eq!(samples.count(), asdu.sample.len() / 8);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((_, pdu))) = sv::decode_frame(data) {
        walk(&pdu);
    }
    if let Ok((_, pdu)) = sv::decode_payload(data) {
        walk(&pdu);
    }
    if let Ok(pdu) = sv::decode_pdu(data) {
        walk(&pdu);
    }
});
