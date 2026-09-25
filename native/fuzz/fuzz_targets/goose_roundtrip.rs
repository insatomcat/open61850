// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Any GOOSE message and address through the encoder: no panic, and a frame
//! it writes decodes to the same fields and the same values.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use open61850_core::data::Data;
use open61850_core::ethernet::{Address, Vlan};
use open61850_core::goose::{self, GoosePdu};
use open61850_core::time::UtcTime;

/// Tags that decode as Raw (not one the decoder interprets, nor a structure or an array).
const RAW_TAGS: [u32; 6] = [0x00, 0x8B, 0x8E, 0x90, 0x9F20, 0xBF48];

#[derive(Arbitrary, Debug)]
enum Value {
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Float32(u32),
    Float64(u64),
    BitString(Vec<u8>, u8),
    Octets(Vec<u8>),
    Visible(Vec<u8>),
    Mms(Vec<u8>),
    Utc(u32, u32, u8),
    Binary([u8; 6]),
    Structure(u8),
    Array(u8),
    Raw(u8, Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    gocb_ref: Vec<u8>,
    tal: u32,
    dat_set: Vec<u8>,
    go_id: Option<Vec<u8>>,
    t: (u32, u32, u8),
    st_num: u32,
    sq_num: u32,
    simulation: bool,
    conf_rev: u32,
    nds_com: bool,
    entries: u32,
    values: Vec<Value>,
    app_id: u16,
    vlan: Option<(u16, u8)>,
}

fn data(v: &Value) -> Data<'_> {
    match v {
        Value::Boolean(b) => Data::Boolean(*b),
        Value::Integer(i) => Data::Integer(*i),
        Value::Unsigned(u) => Data::Unsigned(*u),
        Value::Float32(bits) => Data::Float32(f32::from_bits(*bits)),
        Value::Float64(bits) => Data::Float64(f64::from_bits(*bits)),
        Value::BitString(bits, unused) => Data::BitString { bits, unused: *unused },
        Value::Octets(s) => Data::OctetString(s),
        Value::Visible(s) => Data::VisibleString(s),
        Value::Mms(s) => Data::MmsString(s),
        Value::Utc(s, f, q) => Data::UtcTime(UtcTime { seconds: *s, fraction: f & 0xFF_FFFF, quality: *q }),
        Value::Binary(t) => Data::BinaryTime(*t),
        Value::Structure(n) => Data::Structure(usize::from(*n)),
        Value::Array(n) => Data::Array(usize::from(*n)),
        Value::Raw(tag, value) => Data::Raw { tag: RAW_TAGS[usize::from(*tag) % RAW_TAGS.len()], value },
    }
}

/// Equal, floats compared by their bits (NaN included).
fn same(a: &Data<'_>, b: &Data<'_>) -> bool {
    match (a, b) {
        (Data::Float32(x), Data::Float32(y)) => x.to_bits() == y.to_bits(),
        (Data::Float64(x), Data::Float64(y)) => x.to_bits() == y.to_bits(),
        _ => a == b,
    }
}

fuzz_target!(|input: Input| {
    let values: Vec<Data<'_>> = input.values.iter().map(data).collect();
    let t = UtcTime { seconds: input.t.0, fraction: input.t.1 & 0xFF_FFFF, quality: input.t.2 };
    let pdu = GoosePdu {
        gocb_ref: &input.gocb_ref,
        time_allowed_to_live: input.tal,
        dat_set: &input.dat_set,
        go_id: input.go_id.as_deref(),
        t,
        st_num: input.st_num,
        sq_num: input.sq_num,
        simulation: input.simulation,
        conf_rev: input.conf_rev,
        nds_com: input.nds_com,
        num_dat_set_entries: input.entries,
        all_data: values.as_slice(),
    };
    let address = Address {
        dst_mac: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
        src_mac: [0x02, 0, 0, 0, 0, 0x01],
        app_id: input.app_id,
        vlan: input.vlan.map(|(id, priority)| Vlan { id, priority }),
    };
    let mut buf = vec![0u8; 70_000];
    let Ok(n) = goose::encode_frame(&pdu, &address, &mut buf) else { return };
    assert_eq!(goose::pdu_len(&pdu).unwrap() + address.header_len(), n);
    let (frame, m) = goose::decode_frame(&buf[..n]).unwrap().unwrap();
    assert_eq!((frame.header.app_id, frame.vlan_id), (input.app_id, input.vlan.map(|v| v.0)));
    assert_eq!((m.gocb_ref, m.dat_set, m.go_id, m.t), (pdu.gocb_ref, pdu.dat_set, pdu.go_id, t));
    assert_eq!(
        (m.time_allowed_to_live, m.st_num, m.sq_num, m.conf_rev, m.num_dat_set_entries),
        (u64::from(input.tal), u64::from(input.st_num), u64::from(input.sq_num), u64::from(input.conf_rev), u64::from(input.entries))
    );
    assert_eq!((m.simulation, m.nds_com), (input.simulation, input.nds_com));
    let decoded: Vec<Data<'_>> = m.values().collect();
    assert_eq!(decoded.len(), values.len());
    for (a, b) in values.iter().zip(&decoded) {
        assert!(same(a, b), "{a:?} became {b:?}");
    }
});
