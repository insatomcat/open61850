// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Cost of decoding an SV frame with open61850-core, on the frame
//! `tools/bench_sv_decode.py` measures in Python (6I3U, 2 ASDUs, VLAN tagged).
//!
//!     cargo run --release -p open61850-core --example bench_sv_decode

use std::hint::black_box;
use std::time::Instant;

use open61850_core::sv;

const FRAME: &str = "010ccd0400010011223344558100806488ba400000cf000000006081c4800102a281be305d800453565f31820200008304\
0000271085010287480000000000000000000003e800000000000007d00000000000000bb80000000000000fa000000000000013880000\
0000000017700000000000001b580000000000001f4000000000305d800453565f318202000183040000271085010287480000000000000\
000000003e800000000000007d00000000000000bb80000000000000fa0000000000000138800000000000017700000000000001b580000\
000000001f4000000000";

fn decode(frame: &[u8]) -> i64 {
    let (_, pdu) = sv::decode_frame(frame).unwrap().unwrap();
    let mut sum = 0i64;
    for asdu in pdu.asdus() {
        sum += i64::from(asdu.smp_cnt);
        for (value, quality) in sv::int32_samples(asdu.sample).unwrap() {
            sum += i64::from(value) + i64::from(quality);
        }
    }
    sum
}

fn main() {
    let frame: Vec<u8> = (0..FRAME.len()).step_by(2).map(|i| u8::from_str_radix(&FRAME[i..i + 2], 16).unwrap()).collect();
    let n = 2_000_000;
    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        let mut acc = 0i64;
        for _ in 0..n {
            acc = acc.wrapping_add(decode(black_box(&frame)));
        }
        black_box(acc);
        best = best.min(start.elapsed().as_secs_f64() / f64::from(n));
    }
    println!("{}-byte frame, 2 ASDU: {:.0} ns/frame", frame.len(), best * 1e9);
}
