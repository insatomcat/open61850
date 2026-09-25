// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Cost of encoding, then decoding (values read), a trip GOOSE frame with
//! open61850-core: 10 allData entries (5 booleans, each with its Quality),
//! VLAN tagged.
//!
//!     cargo run --release -p open61850-core --example bench_goose

use std::hint::black_box;
use std::time::Instant;

use open61850_core::data::Data;
use open61850_core::ethernet::{Address, Vlan};
use open61850_core::goose::{self, GoosePdu};
use open61850_core::time::UtcTime;

fn main() {
    let quality = Data::BitString { bits: &[0, 0], unused: 3 };
    let mut all_data = [quality; 10];
    for (i, entry) in all_data.iter_mut().step_by(2).enumerate() {
        *entry = Data::Boolean(i == 0);
    }
    let address = Address {
        dst_mac: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
        src_mac: [0x02, 0, 0, 0, 0, 0x01],
        app_id: 0x0001,
        vlan: Some(Vlan { id: 5, priority: 4 }),
    };
    let mut buf = [0u8; 512];
    let n = 2_000_000u32;
    let mut best = f64::MAX;
    let mut len = 0;
    for _ in 0..5 {
        let start = Instant::now();
        for sq in 0..n {
            let pdu = GoosePdu {
                gocb_ref: b"IED01PROT/LLN0$GO$gcbTrip",
                time_allowed_to_live: 2000,
                dat_set: b"IED01PROT/LLN0$DS_TRIP",
                go_id: Some(b"IED01_TRIP"),
                t: UtcTime { seconds: 1_790_000_000, fraction: 0x40_0000, quality: 0x0A },
                st_num: 7,
                sq_num: black_box(sq),
                simulation: false,
                conf_rev: 1,
                nds_com: false,
                num_dat_set_entries: 10,
                all_data: black_box(&all_data),
            };
            len = goose::encode_frame(&pdu, &address, black_box(&mut buf)).unwrap();
        }
        best = best.min(start.elapsed().as_secs_f64() / f64::from(n));
    }
    println!("{len}-byte trip frame, 10 entries: encoded in {:.0} ns", best * 1e9);

    let frame = &buf[..len];
    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        let mut trips = 0u64;
        for _ in 0..n {
            let (_, message) = goose::decode_frame(black_box(frame)).unwrap().unwrap();
            trips += message.st_num;
            for value in message.values() {
                if value == Data::Boolean(true) {
                    trips += 1;
                }
            }
        }
        black_box(trips);
        best = best.min(start.elapsed().as_secs_f64() / f64::from(n));
    }
    println!("{len}-byte trip frame, 10 entries: decoded in {:.0} ns", best * 1e9);
}
