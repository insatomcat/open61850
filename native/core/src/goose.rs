// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! GOOSE encoding (IEC 61850-8-1, clause A.3 `IECGoosePdu`), as
//! `open61850.goose` writes it, octet for octet.
//!
//! ```text
//! IECGoosePdu ::= [APPLICATION 1] IMPLICIT SEQUENCE {
//!     gocbRef [0], timeAllowedtoLive [1], datSet [2], goID [3] OPTIONAL,
//!     t [4] UtcTime, stNum [5], sqNum [6], simulation [7], confRev [8],
//!     ndsCom [9], numDatSetEntries [10], allData [11] SEQUENCE OF Data }
//! ```
//!
//! [`encode_frame`] writes the whole Ethernet frame into the caller's
//! buffer and returns its length: no allocation, no intermediate copy.
//! State (stNum, sqNum, t) and retransmission belong to the caller.

use core::fmt;

use crate::ber::{BufferFull, Integer, Writer};
use crate::data::{self, Data, DataError};
use crate::ethernet::{Address, FrameError, ETHERTYPE_GOOSE};
use crate::time::UtcTime;

pub const TAG_GOOSE_PDU: u32 = 0x61;
const TAG_ALL_DATA: u32 = 0xAB;

/// Content of one GOOSE message. Strings are the VisibleString octets.
///
/// `num_dat_set_entries` is written as given; it normally counts the
/// top-level values of `all_data`, a preorder sequence (see [`crate::data`]).
/// allData is left out when `all_data` is empty.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GoosePdu<'a> {
    pub gocb_ref: &'a [u8],
    pub time_allowed_to_live: u32,
    pub dat_set: &'a [u8],
    pub go_id: Option<&'a [u8]>,
    pub t: UtcTime,
    pub st_num: u32,
    pub sq_num: u32,
    pub simulation: bool,
    pub conf_rev: u32,
    pub nds_com: bool,
    pub num_dat_set_entries: u32,
    pub all_data: &'a [Data<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The buffer is shorter than the `needed` octets.
    BufferTooSmall { needed: usize },
    Data(DataError),
    Frame(FrameError),
}

impl From<DataError> for EncodeError {
    fn from(e: DataError) -> Self {
        EncodeError::Data(e)
    }
}

impl From<BufferFull> for EncodeError {
    // Lengths are measured before writing: only a bug could land here.
    fn from(_: BufferFull) -> Self {
        EncodeError::BufferTooSmall { needed: 0 }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::BufferTooSmall { needed } => write!(f, "buffer too small: {needed} octets needed"),
            EncodeError::Data(DataError::MissingMembers) => f.write_str("a structure or array lacks members"),
            EncodeError::Data(DataError::TooDeep) => {
                write!(f, "structures and arrays nested deeper than {}", data::MAX_DEPTH)
            }
            EncodeError::Data(DataError::UnusedBits(n)) => write!(f, "unused_bits must be 0..7, got {n}"),
            EncodeError::Data(DataError::BufferFull) => f.write_str("buffer full"),
            EncodeError::Frame(FrameError::ApduTooLong(n)) => write!(f, "APDU too long: {n} bytes"),
            EncodeError::Frame(FrameError::VlanId(id)) => write!(f, "VLAN id out of range: {id}"),
            EncodeError::Frame(FrameError::VlanPriority(p)) => write!(f, "VLAN priority out of range: {p}"),
        }
    }
}

struct Fields {
    tal: Integer,
    st_num: Integer,
    sq_num: Integer,
    conf_rev: Integer,
    entries: Integer,
    all_data: usize,
}

impl Fields {
    fn of(pdu: &GoosePdu<'_>) -> Result<Fields, DataError> {
        let unsigned = |v: u32| Integer::unsigned(u64::from(v));
        Ok(Fields {
            tal: unsigned(pdu.time_allowed_to_live),
            st_num: unsigned(pdu.st_num),
            sq_num: unsigned(pdu.sq_num),
            conf_rev: unsigned(pdu.conf_rev),
            entries: unsigned(pdu.num_dat_set_entries),
            all_data: data::sequence_len(pdu.all_data)?,
        })
    }

    fn content_len(&self, pdu: &GoosePdu<'_>) -> usize {
        let tlv = |content: usize| crate::ber::tlv_len(0x80, content);
        tlv(pdu.gocb_ref.len())
            + tlv(self.tal.as_slice().len())
            + tlv(pdu.dat_set.len())
            + pdu.go_id.map_or(0, |g| tlv(g.len()))
            + tlv(8)
            + tlv(self.st_num.as_slice().len())
            + tlv(self.sq_num.as_slice().len())
            + tlv(1)
            + tlv(self.conf_rev.as_slice().len())
            + tlv(1)
            + tlv(self.entries.as_slice().len())
            + if pdu.all_data.is_empty() { 0 } else { crate::ber::tlv_len(TAG_ALL_DATA, self.all_data) }
    }

    fn write(&self, pdu: &GoosePdu<'_>, content_len: usize, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let boolean = |v: bool| [if v { 0xFF } else { 0x00 }];
        w.put_header(TAG_GOOSE_PDU, content_len)?;
        w.put_tlv(0x80, pdu.gocb_ref)?;
        w.put_tlv(0x81, self.tal.as_slice())?;
        w.put_tlv(0x82, pdu.dat_set)?;
        if let Some(go_id) = pdu.go_id {
            w.put_tlv(0x83, go_id)?;
        }
        w.put_tlv(0x84, &pdu.t.encode())?;
        w.put_tlv(0x85, self.st_num.as_slice())?;
        w.put_tlv(0x86, self.sq_num.as_slice())?;
        w.put_tlv(0x87, &boolean(pdu.simulation))?;
        w.put_tlv(0x88, self.conf_rev.as_slice())?;
        w.put_tlv(0x89, &boolean(pdu.nds_com))?;
        w.put_tlv(0x8A, self.entries.as_slice())?;
        if !pdu.all_data.is_empty() {
            w.put_header(TAG_ALL_DATA, self.all_data)?;
            data::write_sequence(pdu.all_data, w)?;
        }
        Ok(())
    }
}

/// Octets of the encoded `IECGoosePdu`.
pub fn pdu_len(pdu: &GoosePdu<'_>) -> Result<usize, EncodeError> {
    let fields = Fields::of(pdu)?;
    Ok(crate::ber::tlv_len(TAG_GOOSE_PDU, fields.content_len(pdu)))
}

/// Encode the `IECGoosePdu` into `out`; return its length.
pub fn encode_pdu(pdu: &GoosePdu<'_>, out: &mut [u8]) -> Result<usize, EncodeError> {
    let fields = Fields::of(pdu)?;
    let content_len = fields.content_len(pdu);
    let needed = crate::ber::tlv_len(TAG_GOOSE_PDU, content_len);
    if out.len() < needed {
        return Err(EncodeError::BufferTooSmall { needed });
    }
    fields.write(pdu, content_len, &mut Writer::new(out))?;
    Ok(needed)
}

/// Encode a complete GOOSE Ethernet frame (without FCS or padding) into
/// `out`; return its length.
pub fn encode_frame(pdu: &GoosePdu<'_>, address: &Address, out: &mut [u8]) -> Result<usize, EncodeError> {
    let fields = Fields::of(pdu)?;
    let content_len = fields.content_len(pdu);
    let apdu_len = crate::ber::tlv_len(TAG_GOOSE_PDU, content_len);
    address.check(apdu_len).map_err(EncodeError::Frame)?;
    let needed = address.header_len() + apdu_len;
    if out.len() < needed {
        return Err(EncodeError::BufferTooSmall { needed });
    }
    let mut w = Writer::new(out);
    address.write_header(&mut w, ETHERTYPE_GOOSE, apdu_len)?;
    fields.write(pdu, content_len, &mut w)?;
    Ok(needed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::Vlan;

    // open61850.goose.encode_goose_frame of this message (goID "G1",
    // t = 2026-01-01T00:00:00.5Z with quality 0x0A, allData [bool, Quality]).
    const FRAME: [u8; 98] = [
        0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00, 0x80, 0x05, 0x88, 0xB8,
        0x10, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x61, 0x46, 0x80, 0x10, 0x49, 0x45, 0x44, 0x30, 0x31, 0x4C,
        0x44, 0x30, 0x2F, 0x4C, 0x4C, 0x4E, 0x30, 0x24, 0x47, 0x4F, 0x81, 0x02, 0x07, 0xD0, 0x82, 0x03, 0x44, 0x53,
        0x31, 0x83, 0x02, 0x47, 0x31, 0x84, 0x08, 0x69, 0x55, 0xB9, 0x00, 0x80, 0x00, 0x00, 0x0A, 0x85, 0x02, 0x00,
        0x80, 0x86, 0x01, 0x00, 0x87, 0x01, 0x00, 0x88, 0x01, 0x01, 0x89, 0x01, 0x00, 0x8A, 0x01, 0x02, 0xAB, 0x08,
        0x83, 0x01, 0xFF, 0x84, 0x03, 0x03, 0x00, 0x00,
    ];

    fn message<'a>(all_data: &'a [Data<'a>]) -> GoosePdu<'a> {
        GoosePdu {
            gocb_ref: b"IED01LD0/LLN0$GO",
            time_allowed_to_live: 2000,
            dat_set: b"DS1",
            go_id: Some(b"G1"),
            t: UtcTime { seconds: 1_767_225_600, fraction: 0x80_0000, quality: 0x0A },
            st_num: 128,
            sq_num: 0,
            simulation: false,
            conf_rev: 1,
            nds_com: false,
            num_dat_set_entries: 2,
            all_data,
        }
    }

    const ADDRESS: Address = Address {
        dst_mac: [0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01],
        src_mac: [0x02, 0, 0, 0, 0, 0x01],
        app_id: 0x1000,
        vlan: Some(Vlan { id: 5, priority: 4 }),
    };

    #[test]
    fn frame_as_python_writes_it() {
        let all_data = [Data::Boolean(true), Data::BitString { bits: &[0, 0], unused: 3 }];
        let pdu = message(&all_data);
        let mut buf = [0u8; 256];
        let n = encode_frame(&pdu, &ADDRESS, &mut buf).unwrap();
        assert_eq!(&buf[..n], &FRAME[..]);
        assert_eq!(pdu_len(&pdu), Ok(n - 26));
        assert_eq!(encode_pdu(&pdu, &mut buf), Ok(n - 26));
        assert_eq!(&buf[..n - 26], &FRAME[26..]);
    }

    #[test]
    fn errors() {
        let all_data = [Data::Boolean(true)];
        let pdu = message(&all_data);
        let mut small = [0u8; 50];
        assert_eq!(encode_frame(&pdu, &ADDRESS, &mut small), Err(EncodeError::BufferTooSmall { needed: 93 }));
        let bad = Address { vlan: Some(Vlan { id: 0x1000, priority: 0 }), ..ADDRESS };
        let mut buf = [0u8; 256];
        assert_eq!(encode_frame(&pdu, &bad, &mut buf), Err(EncodeError::Frame(FrameError::VlanId(0x1000))));
        let broken = [Data::Structure(3)];
        assert_eq!(encode_pdu(&message(&broken), &mut buf), Err(EncodeError::Data(DataError::MissingMembers)));
    }
}
