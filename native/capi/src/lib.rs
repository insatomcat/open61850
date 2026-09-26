// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! C API of open61850-core: Sampled Values decoding, GOOSE encoding and
//! decoding for real-time C programs. The header `include/open61850.h` is
//! generated from this file by cbindgen.
//!
//! Every function returns `O61850_OK` (0) or a negative `O61850_ERR_*` code,
//! allocates nothing and keeps no state, so it may be called from any
//! thread. Decoded strings and buffers point into the caller's frame.
//! A panic (a bug) is caught and reported as `O61850_ERR_INTERNAL`.

#![allow(non_camel_case_types)]

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use open61850_core::data::{self, Data, DataList};
use open61850_core::ethernet::{self, Address, Frame, Header, Vlan};
use open61850_core::goose::{self, DecodeError, Deviation, EncodeError, GoosePdu, Received};
use open61850_core::sv::{self, SvError, SvPdu};
use open61850_core::time::UtcTime;

/// Success.
pub const O61850_OK: i32 = 0;
/// A required pointer is NULL.
pub const O61850_ERR_NULL: i32 = -1;
/// The frame carries another EtherType, or is too short to have one.
pub const O61850_ERR_ETHERTYPE: i32 = -2;
/// The APPID header is truncated, or its Length is inconsistent (strict
/// GOOSE decoding: it covers octets after the PDU).
pub const O61850_ERR_HEADER: i32 = -3;
/// Broken BER: a tag, a length, or a TLV running past its parent.
pub const O61850_ERR_BER: i32 = -4;
/// A PDU field is missing, of the wrong size, or has an unexpected tag
/// (strict GOOSE decoding: a header field outside what IEC 61850-8-1 allows).
pub const O61850_ERR_FIELD: i32 = -5;
/// noASDU does not match the ASDUs present.
pub const O61850_ERR_COUNT: i32 = -6;
/// A GOOSE header counter is above 64 bits.
pub const O61850_ERR_TOO_LARGE: i32 = -7;
/// An output buffer or array is too small; the size needed is returned.
pub const O61850_ERR_BUFFER: i32 = -8;
/// allData values to encode are invalid: unknown kind, NULL octets with a
/// non-zero length, a structure lacking members, nesting deeper than 32,
/// a bit string with more than 7 unused bits. GOOSE decoding: broken BER
/// inside allData; strict decoding, allData outside what IEC 61850-8-1
/// allows, or other than numDatSetEntries values.
pub const O61850_ERR_DATA: i32 = -9;
/// Frame parameters out of range: VLAN id above 4095, priority above 7,
/// APDU above 65527 octets.
pub const O61850_ERR_FRAME: i32 = -10;
/// A sample buffer whose length is not a multiple of 8.
pub const O61850_ERR_SAMPLES: i32 = -11;
/// A bug in open61850 (a Rust panic, caught).
pub const O61850_ERR_INTERNAL: i32 = -12;

/// Octets of a string or a buffer. In decoded values, `ptr` points into
/// the caller's frame and is NULL only for an absent optional field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_bytes {
    pub ptr: *const u8,
    pub len: usize,
}

/// MMS UtcTime: seconds since the UNIX epoch, fraction of second in 2^-24
/// units (24 bits), TimeQuality octet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_utc_time {
    pub seconds: u32,
    pub fraction: u32,
    pub quality: u8,
}

/// Ethernet and APPID headers of a received frame.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_frame_info {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub has_vlan: bool,
    pub vlan_id: u16,
    pub vlan_priority: u8,
    pub app_id: u16,
    pub reserved1: u16,
    pub reserved2: u16,
}

/// Where a frame to send goes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_address {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub app_id: u16,
    pub has_vlan: bool,
    pub vlan_id: u16,
    pub vlan_priority: u8,
}

/// One Sampled Values ASDU (IEC 61850-9-2, IEC 61869-9).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_sv_asdu {
    pub sv_id: o61850_bytes,
    /// `ptr` NULL when absent.
    pub dat_set: o61850_bytes,
    pub smp_cnt: u16,
    pub conf_rev: u32,
    pub has_refr_tm: bool,
    pub refr_tm: o61850_utc_time,
    pub smp_synch: u8,
    pub has_smp_rate: bool,
    pub smp_rate: u16,
    /// The seqData octets; `o61850_sv_int32_samples` splits the 9-2LE layout.
    pub sample: o61850_bytes,
    pub has_smp_mod: bool,
    pub smp_mod: u16,
    /// `ptr` NULL when absent; 8 octets in a conformant stream.
    pub gm_identity: o61850_bytes,
}

pub const O61850_DATA_BOOLEAN: u32 = 1;
pub const O61850_DATA_INTEGER: u32 = 2;
pub const O61850_DATA_UNSIGNED: u32 = 3;
pub const O61850_DATA_FLOAT32: u32 = 4;
pub const O61850_DATA_FLOAT64: u32 = 5;
pub const O61850_DATA_BIT_STRING: u32 = 6;
pub const O61850_DATA_OCTET_STRING: u32 = 7;
pub const O61850_DATA_VISIBLE_STRING: u32 = 8;
pub const O61850_DATA_MMS_STRING: u32 = 9;
pub const O61850_DATA_UTC_TIME: u32 = 10;
pub const O61850_DATA_BINARY_TIME: u32 = 11;
pub const O61850_DATA_STRUCTURE: u32 = 12;
pub const O61850_DATA_ARRAY: u32 = 13;
pub const O61850_DATA_RAW: u32 = 14;

/// Bits packed MSB first; `unused` trailing bits of the last octet (0..7).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_bit_string {
    pub bits: o61850_bytes,
    pub unused: u8,
}

/// Any tag (the integer of its identifier octets) with its content.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_raw {
    pub tag: u32,
    pub value: o61850_bytes,
}

/// The value of an `o61850_data`, selected by its kind.
#[repr(C)]
#[derive(Clone, Copy)]
pub union o61850_data_value {
    /// BOOLEAN: 0 is FALSE, anything else TRUE.
    pub boolean: u8,
    pub int64: i64,
    pub uint64: u64,
    pub float32: f32,
    pub float64: f64,
    pub bit_string: o61850_bit_string,
    /// OCTET_STRING, VISIBLE_STRING (ASCII), MMS_STRING (UTF-8).
    pub octets: o61850_bytes,
    pub utc_time: o61850_utc_time,
    /// Milliseconds since midnight (4 octets), days since 1984-01-01 (2).
    pub binary_time: [u8; 6],
    /// STRUCTURE, ARRAY: number of members, which follow in the array.
    pub members: usize,
    pub raw: o61850_raw,
}

/// One MMS Data value. A sequence of values is an array in preorder: a
/// STRUCTURE or an ARRAY of n members is followed by its n members, each
/// followed by its own. `kind` is one of `O61850_DATA_*` (0 is invalid).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_data {
    pub kind: u32,
    pub value: o61850_data_value,
}

/// A GOOSE message to encode. A string with `len` 0 may have a NULL `ptr`;
/// `go_id` is left out when its `ptr` is NULL. `all_data` holds
/// `all_data_len` values in preorder; with none, allData is written empty.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_goose_pdu {
    pub gocb_ref: o61850_bytes,
    pub time_allowed_to_live: u32,
    pub dat_set: o61850_bytes,
    pub go_id: o61850_bytes,
    pub t: o61850_utc_time,
    pub st_num: u32,
    pub sq_num: u32,
    pub simulation: bool,
    pub conf_rev: u32,
    pub nds_com: bool,
    pub num_dat_set_entries: u32,
    pub all_data: *const o61850_data,
    pub all_data_len: usize,
}

/// A received GOOSE message. Counters are INT32U, read up to 64 bits.
/// `entries` counts the top-level values of allData, whose octets
/// `o61850_goose_values` reads.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct o61850_goose_received {
    pub gocb_ref: o61850_bytes,
    pub time_allowed_to_live: u64,
    pub dat_set: o61850_bytes,
    /// `ptr` NULL when absent.
    pub go_id: o61850_bytes,
    pub t: o61850_utc_time,
    pub st_num: u64,
    pub sq_num: u64,
    pub simulation: bool,
    pub conf_rev: u64,
    pub nds_com: bool,
    pub num_dat_set_entries: u64,
    pub entries: usize,
    pub all_data: o61850_bytes,
}

// --- helpers --------------------------------------------------------------------

fn bytes(s: &[u8]) -> o61850_bytes {
    o61850_bytes { ptr: s.as_ptr(), len: s.len() }
}

fn optional(s: Option<&[u8]>) -> o61850_bytes {
    s.map_or(o61850_bytes { ptr: std::ptr::null(), len: 0 }, bytes)
}

/// The octets `ptr[0..len]`; empty when `len` is 0, `None` when `ptr` is NULL otherwise.
///
/// # Safety
/// `ptr` must be valid for `len` octets for `'a`.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

/// Run `f`, turning a panic into `O61850_ERR_INTERNAL`.
fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(O61850_ERR_INTERNAL)
}

fn utc(t: UtcTime) -> o61850_utc_time {
    o61850_utc_time { seconds: t.seconds, fraction: t.fraction, quality: t.quality }
}

fn from_utc(t: o61850_utc_time) -> UtcTime {
    UtcTime { seconds: t.seconds, fraction: t.fraction, quality: t.quality }
}

fn frame_info(frame: &Frame<'_>) -> o61850_frame_info {
    let mut info = header_info(&frame.header);
    info.dst_mac = frame.dst_mac;
    info.src_mac = frame.src_mac;
    info.has_vlan = frame.vlan_id.is_some();
    info.vlan_id = frame.vlan_id.unwrap_or(0);
    info.vlan_priority = frame.vlan_priority.unwrap_or(0);
    info
}

fn header_info(header: &Header<'_>) -> o61850_frame_info {
    o61850_frame_info {
        dst_mac: [0; 6],
        src_mac: [0; 6],
        has_vlan: false,
        vlan_id: 0,
        vlan_priority: 0,
        app_id: header.app_id,
        reserved1: header.reserved1,
        reserved2: header.reserved2,
    }
}

/// Fill `info` with what a refused frame still tells: its MAC addresses
/// (so a receiver can recognise its own emission) and its VLAN tag.
fn partial_info(raw: &[u8]) -> o61850_frame_info {
    let mut info = header_info(&Header { app_id: 0, reserved1: 0, reserved2: 0, apdu: &[] });
    if let (Some(dst), Some(src)) = (raw.get(0..6), raw.get(6..12)) {
        info.dst_mac.copy_from_slice(dst);
        info.src_mac.copy_from_slice(src);
    }
    if raw.get(12..14) == Some(&[0x81, 0x00]) {
        if let Some(&[hi, lo]) = raw.get(14..16) {
            let tci = u16::from_be_bytes([hi, lo]);
            info.has_vlan = true;
            info.vlan_id = tci & 0x0FFF;
            info.vlan_priority = (tci >> 13) as u8;
        }
    }
    info
}

/// Write `value` to `ptr` when it is not NULL.
///
/// # Safety
/// `ptr` must be NULL or valid for a write of `T`.
unsafe fn set<T>(ptr: *mut T, value: T) {
    if !ptr.is_null() {
        ptr.write(value);
    }
}

// --- strings --------------------------------------------------------------------

/// The version of open61850, as a static NUL-terminated string.
#[no_mangle]
pub extern "C" fn o61850_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// A static NUL-terminated description of a return code.
#[no_mangle]
pub extern "C" fn o61850_strerror(code: i32) -> *const c_char {
    let text: &'static str = match code {
        O61850_OK => "success\0",
        O61850_ERR_NULL => "a required pointer is NULL\0",
        O61850_ERR_ETHERTYPE => "another EtherType, or a frame too short to have one\0",
        O61850_ERR_HEADER => "APPID header truncated or with an inconsistent Length\0",
        O61850_ERR_BER => "broken BER: tag, length, or TLV running past its parent\0",
        O61850_ERR_FIELD => "PDU field missing, of the wrong size, or with an unexpected tag\0",
        O61850_ERR_COUNT => "noASDU does not match the ASDUs present\0",
        O61850_ERR_TOO_LARGE => "GOOSE header counter above 64 bits\0",
        O61850_ERR_BUFFER => "output buffer or array too small\0",
        O61850_ERR_DATA => "invalid allData values\0",
        O61850_ERR_FRAME => "frame parameters out of range (VLAN id, priority, APDU length)\0",
        O61850_ERR_SAMPLES => "sample length not a multiple of 8\0",
        O61850_ERR_INTERNAL => "internal error in open61850\0",
        _ => "unknown return code\0",
    };
    text.as_ptr().cast()
}

// --- Sampled Values ---------------------------------------------------------------

fn sv_code(e: SvError) -> i32 {
    match e {
        SvError::Ber(_) => O61850_ERR_BER,
        SvError::Header => O61850_ERR_HEADER,
        SvError::UnexpectedTag { .. } | SvError::MissingField(_) | SvError::BadSize { .. } | SvError::MissingNoAsdu => {
            O61850_ERR_FIELD
        }
        SvError::NoAsduMismatch { .. } => O61850_ERR_COUNT,
        SvError::SampleLength(_) => O61850_ERR_SAMPLES,
    }
}

fn to_c_asdu(a: &sv::Asdu<'_>) -> o61850_sv_asdu {
    o61850_sv_asdu {
        sv_id: bytes(a.sv_id),
        dat_set: optional(a.dat_set),
        smp_cnt: a.smp_cnt,
        conf_rev: a.conf_rev,
        has_refr_tm: a.refr_tm.is_some(),
        refr_tm: utc(a.refr_tm.unwrap_or_default()),
        smp_synch: a.smp_synch,
        has_smp_rate: a.smp_rate.is_some(),
        smp_rate: a.smp_rate.unwrap_or(0),
        sample: bytes(a.sample),
        has_smp_mod: a.smp_mod.is_some(),
        smp_mod: a.smp_mod.unwrap_or(0),
        gm_identity: optional(a.gm_identity),
    }
}

/// The ASDU sink of a C caller: the first `capacity` go to `asdus`.
///
/// # Safety
/// `asdus` valid for `capacity` elements (checked non-NULL when `capacity` > 0).
unsafe fn asdu_sink<'a>(asdus: *mut o61850_sv_asdu, capacity: usize) -> impl FnMut(usize, sv::Asdu<'a>) {
    move |i, a| {
        if i < capacity {
            // SAFETY: i < capacity, and the caller's array holds capacity elements.
            unsafe { asdus.add(i).write(to_c_asdu(&a)) };
        }
    }
}

/// # Safety
/// As `o61850_sv_decode_frame` for the output pointers.
unsafe fn sv_output(pdu: &SvPdu<'_>, security: *mut o61850_bytes, capacity: usize, count: *mut usize) -> i32 {
    set(security, optional(pdu.security));
    set(count, pdu.len());
    if pdu.len() > capacity {
        O61850_ERR_BUFFER
    } else {
        O61850_OK
    }
}

/// Decode a Sampled Values Ethernet frame (destination MAC first, with or
/// without one 802.1Q tag): every ASDU and every field, checked as
/// open61850's Python decoder checks them.
///
/// `info` (headers) and `security` (`ptr` NULL when absent) may be NULL.
/// The first `capacity` ASDUs go to `asdus`, and `count` (may be NULL)
/// receives the number of ASDUs; `O61850_ERR_BUFFER` when it exceeds
/// `capacity`. For a refused frame, `info` holds the MAC addresses and the
/// VLAN tag when present, zeros otherwise, and `asdus` is unspecified.
///
/// # Safety
/// `frame` valid for `len` octets; each non-NULL output pointer valid for a
/// write, `asdus` for `capacity` elements.
#[no_mangle]
pub unsafe extern "C" fn o61850_sv_decode_frame(
    frame: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    security: *mut o61850_bytes,
    asdus: *mut o61850_sv_asdu,
    capacity: usize,
    count: *mut usize,
) -> i32 {
    guard(|| {
        set(count, 0);
        let Some(raw) = input(frame, len) else { return O61850_ERR_NULL };
        set(info, partial_info(raw));
        if ethernet::ethertype(raw) != Some(ethernet::ETHERTYPE_SV) {
            return O61850_ERR_ETHERTYPE;
        }
        if capacity > 0 && asdus.is_null() {
            return O61850_ERR_NULL;
        }
        match sv::decode_frame_with(raw, asdu_sink(asdus, capacity)) {
            Ok(Some((f, pdu))) => {
                set(info, frame_info(&f));
                sv_output(&pdu, security, capacity, count)
            }
            Ok(None) => O61850_ERR_HEADER,
            Err(e) => sv_code(e),
        }
    })
}

/// As `o61850_sv_decode_frame`, from the APPID field (the octets after the
/// EtherType). `info` receives the APPID header only.
///
/// # Safety
/// As `o61850_sv_decode_frame`.
#[no_mangle]
pub unsafe extern "C" fn o61850_sv_decode_payload(
    payload: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    security: *mut o61850_bytes,
    asdus: *mut o61850_sv_asdu,
    capacity: usize,
    count: *mut usize,
) -> i32 {
    guard(|| {
        set(count, 0);
        let Some(raw) = input(payload, len) else { return O61850_ERR_NULL };
        if capacity > 0 && asdus.is_null() {
            return O61850_ERR_NULL;
        }
        match sv::decode_payload_with(raw, asdu_sink(asdus, capacity)) {
            Ok((header, pdu)) => {
                set(info, header_info(&header));
                sv_output(&pdu, security, capacity, count)
            }
            Err(e) => sv_code(e),
        }
    })
}

/// Split a 9-2LE / IEC 61869-9 sample buffer into INT32 values and 32-bit
/// qualities. The first `capacity` channels go to `values` and `qualities`
/// (either may be NULL); `count` (may be NULL) receives the number of
/// channels, `O61850_ERR_BUFFER` when it exceeds `capacity`.
///
/// # Safety
/// `sample` valid for its length; `values` and `qualities` NULL or valid for
/// `capacity` elements.
#[no_mangle]
pub unsafe extern "C" fn o61850_sv_int32_samples(
    sample: o61850_bytes,
    values: *mut i32,
    qualities: *mut u32,
    capacity: usize,
    count: *mut usize,
) -> i32 {
    guard(|| {
        set(count, 0);
        let Some(raw) = input(sample.ptr, sample.len) else { return O61850_ERR_NULL };
        let samples = match sv::int32_samples(raw) {
            Ok(s) => s,
            Err(e) => return sv_code(e),
        };
        let channels = raw.len() / 8;
        set(count, channels);
        for (i, (value, quality)) in samples.take(capacity).enumerate() {
            if !values.is_null() {
                values.add(i).write(value);
            }
            if !qualities.is_null() {
                qualities.add(i).write(quality);
            }
        }
        if channels > capacity {
            O61850_ERR_BUFFER
        } else {
            O61850_OK
        }
    })
}

// --- GOOSE encoding -------------------------------------------------------------

/// The caller's array of values, read in place.
struct CData<'a>(&'a [o61850_data]);

impl<'a> DataList<'a> for CData<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, i: usize) -> Option<Data<'a>> {
        let d = self.0.get(i)?;
        let v = &d.value;
        // SAFETY: the union member read is the one `kind` selects, and the
        // caller keeps the octets valid for the call (see o61850_goose_pdu).
        unsafe {
            Some(match d.kind {
                O61850_DATA_BOOLEAN => Data::Boolean(v.boolean != 0),
                O61850_DATA_INTEGER => Data::Integer(v.int64),
                O61850_DATA_UNSIGNED => Data::Unsigned(v.uint64),
                O61850_DATA_FLOAT32 => Data::Float32(v.float32),
                O61850_DATA_FLOAT64 => Data::Float64(v.float64),
                O61850_DATA_BIT_STRING => {
                    let b = v.bit_string;
                    Data::BitString { bits: input(b.bits.ptr, b.bits.len)?, unused: b.unused }
                }
                O61850_DATA_OCTET_STRING => Data::OctetString(input(v.octets.ptr, v.octets.len)?),
                O61850_DATA_VISIBLE_STRING => Data::VisibleString(input(v.octets.ptr, v.octets.len)?),
                O61850_DATA_MMS_STRING => Data::MmsString(input(v.octets.ptr, v.octets.len)?),
                O61850_DATA_UTC_TIME => Data::UtcTime(from_utc(v.utc_time)),
                O61850_DATA_BINARY_TIME => Data::BinaryTime(v.binary_time),
                O61850_DATA_STRUCTURE => Data::Structure(v.members),
                O61850_DATA_ARRAY => Data::Array(v.members),
                O61850_DATA_RAW => Data::Raw { tag: v.raw.tag, value: input(v.raw.value.ptr, v.raw.value.len)? },
                _ => return None,
            })
        }
    }
}

fn encode_code(e: EncodeError) -> i32 {
    match e {
        EncodeError::BufferTooSmall { .. } => O61850_ERR_BUFFER,
        EncodeError::Data(_) => O61850_ERR_DATA,
        EncodeError::Frame(_) => O61850_ERR_FRAME,
    }
}

/// # Safety
/// As `o61850_goose_encode_frame`.
unsafe fn goose_encode(
    pdu: *const o61850_goose_pdu,
    address: Option<&o61850_address>,
    out: *mut u8,
    out_size: usize,
    out_len: *mut usize,
) -> i32 {
    set(out_len, 0);
    let Some(p) = pdu.as_ref() else { return O61850_ERR_NULL };
    let (Some(gocb_ref), Some(dat_set)) = (input(p.gocb_ref.ptr, p.gocb_ref.len), input(p.dat_set.ptr, p.dat_set.len))
    else {
        return O61850_ERR_NULL;
    };
    let go_id = if p.go_id.ptr.is_null() { None } else { input(p.go_id.ptr, p.go_id.len) };
    let values: &[o61850_data] = if p.all_data_len == 0 {
        &[]
    } else if p.all_data.is_null() {
        return O61850_ERR_NULL;
    } else {
        slice::from_raw_parts(p.all_data, p.all_data_len)
    };
    let all_data = CData(values);
    let message = GoosePdu {
        gocb_ref,
        time_allowed_to_live: p.time_allowed_to_live,
        dat_set,
        go_id,
        t: from_utc(p.t),
        st_num: p.st_num,
        sq_num: p.sq_num,
        simulation: p.simulation,
        conf_rev: p.conf_rev,
        nds_com: p.nds_com,
        num_dat_set_entries: p.num_dat_set_entries,
        all_data: &all_data,
    };
    let address = address.map(|a| Address {
        dst_mac: a.dst_mac,
        src_mac: a.src_mac,
        app_id: a.app_id,
        vlan: a.has_vlan.then_some(Vlan { id: a.vlan_id, priority: a.vlan_priority }),
    });
    let buf: &mut [u8] = if out_size == 0 {
        &mut []
    } else if out.is_null() {
        return O61850_ERR_NULL;
    } else {
        slice::from_raw_parts_mut(out, out_size)
    };
    let written = match &address {
        Some(a) => goose::encode_frame(&message, a, buf),
        None => goose::encode_pdu(&message, buf),
    };
    match written {
        Ok(n) => {
            set(out_len, n);
            O61850_OK
        }
        Err(EncodeError::BufferTooSmall { needed }) => {
            set(out_len, needed);
            O61850_ERR_BUFFER
        }
        Err(e) => encode_code(e),
    }
}

/// Encode a complete GOOSE Ethernet frame (without FCS or padding) into
/// `out`, octet for octet as open61850's Python encoder writes it.
/// `out_len` (may be NULL) receives its length; with `O61850_ERR_BUFFER`,
/// the size needed (pass `out_size` 0 to ask for it). stNum, sqNum, t and
/// retransmission are the caller's.
///
/// # Safety
/// `pdu` and `address` valid, with every octet pointer valid for its length
/// and `all_data` for `all_data_len` values; `out` valid for `out_size`
/// octets; `out_len` NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_encode_frame(
    pdu: *const o61850_goose_pdu,
    address: *const o61850_address,
    out: *mut u8,
    out_size: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        let Some(a) = address.as_ref() else {
            set(out_len, 0);
            return O61850_ERR_NULL;
        };
        goose_encode(pdu, Some(a), out, out_size, out_len)
    })
}

/// As `o61850_goose_encode_frame`, for the IECGoosePdu alone (the APDU).
///
/// # Safety
/// As `o61850_goose_encode_frame`.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_encode_pdu(
    pdu: *const o61850_goose_pdu,
    out: *mut u8,
    out_size: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| goose_encode(pdu, None, out, out_size, out_len))
}

// --- GOOSE decoding -------------------------------------------------------------

fn decode_code(e: DecodeError) -> i32 {
    match e {
        DecodeError::Ber(_) => O61850_ERR_BER,
        DecodeError::Header => O61850_ERR_HEADER,
        DecodeError::UnexpectedTag(_) | DecodeError::MissingField(_) | DecodeError::Time => O61850_ERR_FIELD,
        DecodeError::TooLarge(_) => O61850_ERR_TOO_LARGE,
        DecodeError::EmptyCounter(_) => O61850_ERR_FIELD,
        DecodeError::AllData(_) => O61850_ERR_DATA,
        DecodeError::NotConformant(Deviation::OctetsAfterPdu(_)) => O61850_ERR_HEADER,
        DecodeError::NotConformant(d) if d.in_all_data() => O61850_ERR_DATA,
        DecodeError::NotConformant(_) => O61850_ERR_FIELD,
    }
}

fn received(m: &Received<'_>) -> o61850_goose_received {
    o61850_goose_received {
        gocb_ref: bytes(m.gocb_ref),
        time_allowed_to_live: m.time_allowed_to_live,
        dat_set: bytes(m.dat_set),
        go_id: optional(m.go_id),
        t: utc(m.t),
        st_num: m.st_num,
        sq_num: m.sq_num,
        simulation: m.simulation,
        conf_rev: m.conf_rev,
        nds_com: m.nds_com,
        num_dat_set_entries: m.num_dat_set_entries,
        entries: m.entries,
        all_data: bytes(m.all_data),
    }
}

/// # Safety
/// As `o61850_goose_decode_frame`.
unsafe fn goose_frame(
    frame: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    message: *mut o61850_goose_received,
    strict: bool,
) -> i32 {
    guard(|| {
        if message.is_null() {
            return O61850_ERR_NULL;
        }
        message.write_bytes(0, 1);
        let Some(raw) = input(frame, len) else { return O61850_ERR_NULL };
        set(info, partial_info(raw));
        if ethernet::ethertype(raw) != Some(ethernet::ETHERTYPE_GOOSE) {
            return O61850_ERR_ETHERTYPE;
        }
        let decoded = if strict { goose::decode_frame_strict(raw) } else { goose::decode_frame(raw) };
        match decoded {
            Ok(Some((f, m))) => {
                set(info, frame_info(&f));
                message.write(received(&m));
                O61850_OK
            }
            Ok(None) => O61850_ERR_HEADER,
            Err(e) => decode_code(e),
        }
    })
}

/// # Safety
/// As `o61850_goose_decode_frame`.
unsafe fn goose_payload(
    payload: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    message: *mut o61850_goose_received,
    strict: bool,
) -> i32 {
    guard(|| {
        if message.is_null() {
            return O61850_ERR_NULL;
        }
        message.write_bytes(0, 1);
        let Some(raw) = input(payload, len) else { return O61850_ERR_NULL };
        let decoded = if strict { goose::decode_payload_strict(raw) } else { goose::decode_payload(raw) };
        match decoded {
            Ok((header, m)) => {
                set(info, header_info(&header));
                message.write(received(&m));
                O61850_OK
            }
            Err(e) => decode_code(e),
        }
    })
}

/// Decode a GOOSE Ethernet frame (destination MAC first, with or without
/// one 802.1Q tag): header fields and the TLV structure of allData at any
/// depth, checked as open61850's Python decoder checks them. This decoding
/// is lenient, for diagnosis: a protection function should use
/// `o61850_goose_decode_frame_strict`.
///
/// `info` may be NULL; for a refused frame it holds the MAC addresses and
/// the VLAN tag when present (a receiver can recognise its own emission),
/// zeros otherwise. `message` is zeroed unless the frame is accepted.
///
/// # Safety
/// `frame` valid for `len` octets; `info` NULL or valid for a write;
/// `message` valid for a write.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_decode_frame(
    frame: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    message: *mut o61850_goose_received,
) -> i32 {
    goose_frame(frame, len, info, message, false)
}

/// As `o61850_goose_decode_frame`, then refuse what IEC 61850-8-1 forbids.
/// `O61850_ERR_HEADER`: octets after the PDU. `O61850_ERR_FIELD`: a field
/// tag other than 80..8a and ab, fields out of order, gocbRef, datSet or
/// goID longer than 129 characters or outside the VisibleString alphabet,
/// gocbRef empty, t other than 8 octets, a counter above 32 bits,
/// simulation or ndsCom other than one octet, allData missing.
/// `O61850_ERR_DATA`: numDatSetEntries other than the number of entries,
/// an allData value of another class or form than a Data, a BOOLEAN,
/// float or time of the wrong size, a BIT STRING with no valid
/// unused-bits octet, an empty INTEGER, a VisibleString outside its
/// alphabet. Any depth and any definite length form are accepted.
///
/// # Safety
/// As `o61850_goose_decode_frame`.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_decode_frame_strict(
    frame: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    message: *mut o61850_goose_received,
) -> i32 {
    goose_frame(frame, len, info, message, true)
}

/// As `o61850_goose_decode_frame`, from the APPID field (the octets after
/// the EtherType). `info` receives the APPID header only.
///
/// # Safety
/// As `o61850_goose_decode_frame`.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_decode_payload(
    payload: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    message: *mut o61850_goose_received,
) -> i32 {
    goose_payload(payload, len, info, message, false)
}

/// As `o61850_goose_decode_frame_strict`, from the APPID field.
///
/// # Safety
/// As `o61850_goose_decode_frame`.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_decode_payload_strict(
    payload: *const u8,
    len: usize,
    info: *mut o61850_frame_info,
    message: *mut o61850_goose_received,
) -> i32 {
    goose_payload(payload, len, info, message, true)
}

fn to_c(value: Data<'_>) -> o61850_data {
    let (kind, value) = match value {
        Data::Boolean(v) => (O61850_DATA_BOOLEAN, o61850_data_value { boolean: u8::from(v) }),
        Data::Integer(v) => (O61850_DATA_INTEGER, o61850_data_value { int64: v }),
        Data::Unsigned(v) => (O61850_DATA_UNSIGNED, o61850_data_value { uint64: v }),
        Data::Float32(v) => (O61850_DATA_FLOAT32, o61850_data_value { float32: v }),
        Data::Float64(v) => (O61850_DATA_FLOAT64, o61850_data_value { float64: v }),
        Data::BitString { bits, unused } => {
            (O61850_DATA_BIT_STRING, o61850_data_value { bit_string: o61850_bit_string { bits: bytes(bits), unused } })
        }
        Data::OctetString(s) => (O61850_DATA_OCTET_STRING, o61850_data_value { octets: bytes(s) }),
        Data::VisibleString(s) => (O61850_DATA_VISIBLE_STRING, o61850_data_value { octets: bytes(s) }),
        Data::MmsString(s) => (O61850_DATA_MMS_STRING, o61850_data_value { octets: bytes(s) }),
        Data::UtcTime(t) => (O61850_DATA_UTC_TIME, o61850_data_value { utc_time: utc(t) }),
        Data::BinaryTime(t) => (O61850_DATA_BINARY_TIME, o61850_data_value { binary_time: t }),
        Data::Structure(n) => (O61850_DATA_STRUCTURE, o61850_data_value { members: n }),
        Data::Array(n) => (O61850_DATA_ARRAY, o61850_data_value { members: n }),
        Data::Raw { tag, value } => (O61850_DATA_RAW, o61850_data_value { raw: o61850_raw { tag, value: bytes(value) } }),
    };
    o61850_data { kind, value }
}

/// Read the allData values of a decoded message (its `all_data`) in
/// preorder. The first `capacity` values go to `values`; `count` (may be
/// NULL) receives the number of values, `O61850_ERR_BUFFER` when it exceeds
/// `capacity`. An INTEGER or unsigned beyond 64 bits comes out as RAW.
///
/// `all_data` must come from an accepted message: other octets are read up
/// to their first malformed TLV.
///
/// # Safety
/// `all_data` valid for its length; `values` NULL or valid for `capacity`
/// elements; `count` NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn o61850_goose_values(
    all_data: o61850_bytes,
    values: *mut o61850_data,
    capacity: usize,
    count: *mut usize,
) -> i32 {
    guard(|| {
        set(count, 0);
        let Some(raw) = input(all_data.ptr, all_data.len) else { return O61850_ERR_NULL };
        if capacity > 0 && values.is_null() {
            return O61850_ERR_NULL;
        }
        let mut n = 0;
        for value in data::iter_sequence(raw) {
            if n < capacity {
                values.add(n).write(to_c(value));
            }
            n += 1;
        }
        set(count, n);
        if n > capacity {
            O61850_ERR_BUFFER
        } else {
            O61850_OK
        }
    })
}
