// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Ethernet II / IEEE 802.1Q framing shared by GOOSE and Sampled Values, as
//! `open61850.ethernet.parse_frame` reads it.
//!
//! After the MAC addresses and the optional VLAN tag:
//! `EtherType (2) | APPID (2) | Length (2) | Reserved 1 (2) | Reserved 2 (2) | APDU`.
//! `Length` counts from APPID to the end of the APDU; trailing Ethernet
//! padding is ignored.

pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_GOOSE: u16 = 0x88B8;
pub const ETHERTYPE_GSE_MGMT: u16 = 0x88B9;
pub const ETHERTYPE_SV: u16 = 0x88BA;

const HEADER_LEN: usize = 8;

/// The APPID header and the APDU it frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub app_id: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub apdu: &'a [u8],
}

/// A GOOSE or SV frame, up to the APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub vlan_priority: Option<u8>,
    pub ethertype: u16,
    pub header: Header<'a>,
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    match *data.get(at..at + 2)? {
        [a, b] => Some(u16::from_be_bytes([a, b])),
        _ => None,
    }
}

fn mac_at(data: &[u8], at: usize) -> Option<[u8; 6]> {
    match *data.get(at..at + 6)? {
        [a, b, c, d, e, f] => Some([a, b, c, d, e, f]),
        _ => None,
    }
}

/// Parse the bytes after the EtherType; `None` when they are too short or
/// `Length` is inconsistent.
pub fn parse_header(payload: &[u8]) -> Option<Header<'_>> {
    let length = usize::from(u16_at(payload, 2)?);
    if payload.len() < HEADER_LEN || length < HEADER_LEN || length > payload.len() {
        return None;
    }
    Some(Header {
        app_id: u16_at(payload, 0)?,
        reserved1: u16_at(payload, 4)?,
        reserved2: u16_at(payload, 6)?,
        apdu: &payload[HEADER_LEN..length],
    })
}

/// Parse a frame carrying one of `ethertypes`; `None` otherwise, and for
/// truncated frames or an inconsistent `Length`.
pub fn parse_frame<'a>(raw: &'a [u8], ethertypes: &[u16]) -> Option<Frame<'a>> {
    let mut offset = 12;
    let mut ethertype = u16_at(raw, offset)?;
    offset += 2;
    let (mut vlan_id, mut vlan_priority) = (None, None);
    if ethertype == ETHERTYPE_VLAN {
        let tci = u16_at(raw, offset)?;
        vlan_id = Some(tci & 0x0FFF);
        vlan_priority = Some((tci >> 13) as u8);
        ethertype = u16_at(raw, offset + 2)?;
        offset += 4;
    }
    if !ethertypes.contains(&ethertype) {
        return None;
    }
    Some(Frame {
        dst_mac: mac_at(raw, 0)?,
        src_mac: mac_at(raw, 6)?,
        vlan_id,
        vlan_priority,
        ethertype,
        header: parse_header(&raw[offset..])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_frame_with_padding() {
        let mut raw = [0u8; 30];
        raw[12..14].copy_from_slice(&[0x81, 0x00]);
        raw[14..16].copy_from_slice(&[0x80, 0x64]); // priority 4, VLAN 100
        raw[16..18].copy_from_slice(&[0x88, 0xBA]);
        raw[18..22].copy_from_slice(&[0x40, 0x00, 0x00, 0x0A]); // APPID 0x4000, Length 10
        raw[26..28].copy_from_slice(&[0x60, 0x00]);
        let f = parse_frame(&raw, &[ETHERTYPE_SV]).unwrap();
        assert_eq!((f.vlan_id, f.vlan_priority, f.header.app_id), (Some(100), Some(4), 0x4000));
        assert_eq!(f.header.apdu, &[0x60, 0x00]);
        assert!(parse_frame(&raw, &[ETHERTYPE_GOOSE]).is_none());
        raw[21] = 0x0D; // Length past the end
        assert!(parse_frame(&raw[..28], &[ETHERTYPE_SV]).is_none());
    }
}
