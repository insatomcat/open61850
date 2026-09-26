// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! GOOSE (IEC 61850-8-1, clause A.3 `IECGoosePdu`), read as
//! `open61850.goose` reads it and written as it writes it, octet for octet.
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
//!
//! [`decode_pdu`] checks the header fields and the TLV structure of allData
//! at any depth, then [`Received::values`] reads the values without
//! allocating. It is lenient, for diagnosis; [`decode_pdu_strict`] (and its
//! `_payload` and `_frame` variants) also refuses what IEC 61850-8-1 does not
//! allow, as a protection function should before acting on a message.

use core::fmt;

use crate::ber::{self, BerError, BufferFull, Integer, Writer};
use crate::data::{self, Data, DataError, DataList};
use crate::ethernet::{self, Address, Frame, FrameError, Header, ETHERTYPE_GOOSE};
use crate::time::UtcTime;

pub const TAG_GOOSE_PDU: u32 = 0x61;
const TAG_ALL_DATA: u32 = 0xAB;

/// Content of one GOOSE message. Strings are the VisibleString octets.
///
/// `num_dat_set_entries` is written as given; it normally counts the
/// top-level values of `all_data`, a preorder sequence (see [`crate::data`]):
/// a slice of [`Data`] by default, or any [`DataList`]. allData is written
/// even when `all_data` is empty (`ab 00`): it is not OPTIONAL in 8-1.
pub struct GoosePdu<'a, D: DataList<'a> + ?Sized = [Data<'a>]> {
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
    pub all_data: &'a D,
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
    fn of<'a, D: DataList<'a> + ?Sized>(pdu: &GoosePdu<'a, D>) -> Result<Fields, DataError> {
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

    fn content_len<'a, D: DataList<'a> + ?Sized>(&self, pdu: &GoosePdu<'a, D>) -> usize {
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
            + crate::ber::tlv_len(TAG_ALL_DATA, self.all_data)
    }

    fn write<'a, D: DataList<'a> + ?Sized>(
        &self,
        pdu: &GoosePdu<'a, D>,
        content_len: usize,
        w: &mut Writer<'_>,
    ) -> Result<(), EncodeError> {
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
        w.put_header(TAG_ALL_DATA, self.all_data)?;
        data::write_sequence(pdu.all_data, w)?;
        Ok(())
    }
}

/// Octets of the encoded `IECGoosePdu`.
pub fn pdu_len<'a, D: DataList<'a> + ?Sized>(pdu: &GoosePdu<'a, D>) -> Result<usize, EncodeError> {
    let fields = Fields::of(pdu)?;
    Ok(crate::ber::tlv_len(TAG_GOOSE_PDU, fields.content_len(pdu)))
}

/// Encode the `IECGoosePdu` into `out`; return its length.
pub fn encode_pdu<'a, D: DataList<'a> + ?Sized>(pdu: &GoosePdu<'a, D>, out: &mut [u8]) -> Result<usize, EncodeError> {
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
pub fn encode_frame<'a, D: DataList<'a> + ?Sized>(
    pdu: &GoosePdu<'a, D>,
    address: &Address,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
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

// --- decoding -----------------------------------------------------------------

const GOCB_REF: usize = 0;
const TAL: usize = 1;
const DAT_SET: usize = 2;
const GO_ID: usize = 3;
const T: usize = 4;
const ST_NUM: usize = 5;
const SQ_NUM: usize = 6;
const SIMULATION: usize = 7;
const CONF_REV: usize = 8;
const NDS_COM: usize = 9;
const NUM_ENTRIES: usize = 10;
const ALL_DATA: usize = 11;

const MANDATORY: [(usize, &str); 8] = [
    (GOCB_REF, "gocbRef"),
    (TAL, "timeAllowedtoLive"),
    (DAT_SET, "datSet"),
    (T, "t"),
    (ST_NUM, "stNum"),
    (SQ_NUM, "sqNum"),
    (CONF_REV, "confRev"),
    (NUM_ENTRIES, "numDatSetEntries"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Ber(BerError),
    /// The bytes after the EtherType are too short, or their Length is inconsistent.
    Header,
    UnexpectedTag(u32),
    MissingField(&'static str),
    /// A header counter above 64 bits.
    TooLarge(&'static str),
    /// A header counter without content octets.
    EmptyCounter(&'static str),
    /// Broken BER inside allData (a structure's members overrunning it...).
    AllData(BerError),
    /// t shorter than 8 octets.
    Time,
    /// Readable, but not what IEC 61850-8-1 allows (strict decoding only).
    NotConformant(Deviation),
}

/// What the strict decoding refuses in a message the lenient one accepts,
/// in the order it checks (see `open61850.goose._check_strict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deviation {
    /// Octets after the PDU: the header Length does not cover it exactly.
    OctetsAfterPdu(usize),
    /// A field tag other than `80`..`8a` or `ab`.
    NotAField(u32),
    OutOfOrder { field: u32, after: u32 },
    /// gocbRef, datSet or goID longer than 129 or outside the VisibleString alphabet.
    NotVisibleString129(&'static str),
    EmptyGocbRef,
    /// t of another size than 8 octets.
    TimeSize(usize),
    /// An INT32U counter above 32 bits (more than 5 octets, or 5 without a leading `00`).
    Above32Bits(&'static str),
    /// simulation or ndsCom of another size than one octet.
    BooleanSize(&'static str, usize),
    NoAllData,
    EntriesMismatch { declared: u64, present: usize },
    /// An allData tag that is not a Data: another class, a high tag number,
    /// or the wrong form (constructed for a structure or an array only).
    NotAData(u32),
    /// A BOOLEAN, float or time of another size than its type fixes.
    DataSize(u32, usize),
    BitStringUnused,
    EmptyInteger,
    DataNotVisible,
}

impl Deviation {
    /// The deviation lies in allData (the others lie in the header fields or the envelope).
    pub fn in_all_data(&self) -> bool {
        matches!(
            self,
            Deviation::EntriesMismatch { .. }
                | Deviation::NotAData(_)
                | Deviation::DataSize(..)
                | Deviation::BitStringUnused
                | Deviation::EmptyInteger
                | Deviation::DataNotVisible
        )
    }
}

impl fmt::Display for Deviation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Deviation::OctetsAfterPdu(n) => write!(f, "{n} octets after the PDU"),
            Deviation::NotAField(tag) => write!(f, "tag 0x{tag:X} is not a GOOSE field"),
            Deviation::OutOfOrder { field, after } => write!(f, "field [{field}] after [{after}]"),
            Deviation::NotVisibleString129(name) => write!(f, "{name} is not a VisibleString129"),
            Deviation::EmptyGocbRef => f.write_str("empty gocbRef"),
            Deviation::TimeSize(n) => write!(f, "t of {n} octets"),
            Deviation::Above32Bits(name) => write!(f, "{name} above 32 bits"),
            Deviation::BooleanSize(name, n) => write!(f, "{name} of {n} octets"),
            Deviation::NoAllData => f.write_str("no allData"),
            Deviation::EntriesMismatch { declared, present } => {
                write!(f, "numDatSetEntries={declared} but {present} entries")
            }
            Deviation::NotAData(tag) => write!(f, "allData tag 0x{tag:X} is not a Data"),
            Deviation::DataSize(tag, n) => write!(f, "allData value 0x{tag:X} of {n} octets"),
            Deviation::BitStringUnused => f.write_str("allData BIT STRING without a valid unused-bits octet"),
            Deviation::EmptyInteger => f.write_str("empty allData INTEGER"),
            Deviation::DataNotVisible => f.write_str("allData VisibleString outside its alphabet"),
        }
    }
}

impl From<BerError> for DecodeError {
    fn from(e: BerError) -> Self {
        DecodeError::Ber(e)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Ber(e) => e.fmt(f),
            DecodeError::Header => f.write_str("GOOSE header too short or with an inconsistent Length"),
            DecodeError::UnexpectedTag(tag) => write!(f, "expected tag 0x61, found 0x{tag:X}"),
            DecodeError::MissingField(name) => write!(f, "missing mandatory GOOSE field {name}"),
            DecodeError::TooLarge(name) => write!(f, "{name} above 64 bits"),
            DecodeError::EmptyCounter(name) => write!(f, "empty INTEGER ({name})"),
            DecodeError::AllData(e) => e.fmt(f),
            DecodeError::Time => f.write_str("utc-time needs 8 bytes"),
            DecodeError::NotConformant(d) => write!(f, "not conformant: {d}"),
        }
    }
}

/// A checked GOOSE message; strings are raw VisibleString octets.
///
/// Counters are INT32U in IEC 61850-8-1; they are read leniently (with or
/// without the leading `00`) up to 64 bits. `simulation` and `nds_com` are
/// false when absent. `all_data` holds the allData content, already checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received<'a> {
    pub gocb_ref: &'a [u8],
    pub time_allowed_to_live: u64,
    pub dat_set: &'a [u8],
    pub go_id: Option<&'a [u8]>,
    pub t: UtcTime,
    pub st_num: u64,
    pub sq_num: u64,
    pub simulation: bool,
    pub conf_rev: u64,
    pub nds_com: bool,
    pub num_dat_set_entries: u64,
    /// Top-level values in allData (numDatSetEntries is not checked against it).
    pub entries: usize,
    pub all_data: &'a [u8],
}

impl<'a> Received<'a> {
    /// The allData values in preorder (see [`crate::data`]).
    pub fn values(&self) -> data::Values<'a> {
        data::iter_sequence(self.all_data)
    }
}

/// Number of a tag from its identifier octets at `offset` (class and form
/// ignored, as `open61850.ber.tag_number` computes it); `u32::MAX` above 32 bits.
fn tag_number_at(data: &[u8], offset: usize) -> u32 {
    let Some(&first) = data.get(offset) else { return u32::MAX };
    if first & 0x1F != 0x1F {
        return u32::from(first & 0x1F);
    }
    let mut number = 0u32;
    for &b in data.get(offset + 1..).unwrap_or(&[]) {
        number = if number > u32::MAX >> 7 { u32::MAX } else { (number << 7) | u32::from(b & 0x7F) };
        if b & 0x80 == 0 {
            break;
        }
    }
    number
}

fn counter(content: &[u8], name: &'static str) -> Result<u64, DecodeError> {
    ber::decode_unsigned(content).map_err(|e| match e {
        BerError::IntegerTooLarge => DecodeError::TooLarge(name),
        BerError::EmptyInteger => DecodeError::EmptyCounter(name),
        e => DecodeError::Ber(e),
    })
}

fn lenient_bool(content: Option<&[u8]>) -> bool {
    content.and_then(|c| c.first()).is_some_and(|&b| b != 0)
}

/// Decode and check an `IECGoosePdu` (the bytes after the 8-byte APPID header).
///
/// Fields are found by tag number whatever their class and form; the last
/// occurrence wins and other numbers are skipped. Bytes after the PDU TLV
/// are ignored.
pub fn decode_pdu(apdu: &[u8]) -> Result<Received<'_>, DecodeError> {
    let outer = ber::decode_tlv(apdu, 0)?;
    if outer.tag != TAG_GOOSE_PDU {
        return Err(DecodeError::UnexpectedTag(outer.tag));
    }
    let content = outer.value;
    let mut fields: [Option<&[u8]>; 12] = [None; 12];
    let mut at = 0;
    while at < content.len() {
        let tlv = ber::decode_tlv(content, at)?;
        if let Some(slot) = fields.get_mut(tag_number_at(content, at) as usize) {
            *slot = Some(tlv.value);
        }
        at = tlv.end;
    }
    for (number, name) in MANDATORY {
        if fields[number].is_none() {
            return Err(DecodeError::MissingField(name));
        }
    }
    let field = |n: usize| fields[n].unwrap_or(&[]);
    let all_data = field(ALL_DATA);
    Ok(Received {
        gocb_ref: field(GOCB_REF),
        time_allowed_to_live: counter(field(TAL), "timeAllowedtoLive")?,
        dat_set: field(DAT_SET),
        go_id: fields[GO_ID],
        t: UtcTime::decode(field(T)).ok_or(DecodeError::Time)?,
        st_num: counter(field(ST_NUM), "stNum")?,
        sq_num: counter(field(SQ_NUM), "sqNum")?,
        simulation: lenient_bool(fields[SIMULATION]),
        conf_rev: counter(field(CONF_REV), "confRev")?,
        nds_com: lenient_bool(fields[NDS_COM]),
        num_dat_set_entries: counter(field(NUM_ENTRIES), "numDatSetEntries")?,
        entries: data::check_sequence(all_data).map_err(DecodeError::AllData)?,
        all_data,
    })
}

const STRING_MAX: usize = 129; // VisibleString129: gocbRef, datSet, goID
const U32_OCTETS: usize = 5; // an INT32U: 4 octets, and a leading 00 when the high bit is set

fn visible(value: &[u8]) -> bool {
    value.iter().all(|&c| (0x20..=0x7E).contains(&c))
}

/// As [`decode_pdu`], then refuse what IEC 61850-8-1 does not allow.
///
/// The PDU ends where the APDU does (the header Length covers it exactly);
/// fields are the SEQUENCE's: tags `80`..`8a` and `ab` in increasing order,
/// nothing else; gocbRef, datSet and goID are VisibleString129 (gocbRef not
/// empty); t is 8 octets; the counters are INT32U; simulation and ndsCom,
/// when present, are one octet; allData is present and holds
/// numDatSetEntries values, each a context-specific Data, constructed for a
/// structure or an array only, with the size its type fixes (BOOLEAN,
/// floats, times), a BIT STRING of at least one octet and at most 7 unused
/// bits, an INTEGER of at least one octet, a VisibleString in its alphabet.
/// Any depth and any definite length form are accepted.
pub fn decode_pdu_strict(apdu: &[u8]) -> Result<Received<'_>, DecodeError> {
    let message = decode_pdu(apdu)?;
    check_strict(apdu).map_err(DecodeError::NotConformant)?;
    Ok(message)
}

fn check_strict(apdu: &[u8]) -> Result<(), Deviation> {
    // decode_pdu accepted the PDU: its TLVs and allData's structures are well formed.
    let Ok(outer) = ber::decode_tlv(apdu, 0) else { return Ok(()) };
    if outer.end != apdu.len() {
        return Err(Deviation::OctetsAfterPdu(apdu.len() - outer.end));
    }
    let mut fields: [Option<&[u8]>; 12] = [None; 12];
    let mut previous: Option<u32> = None;
    for tlv in ber::iter_tlvs(outer.value).flatten() {
        let number = tlv.tag & 0x1F;
        let expected = if number == ALL_DATA as u32 { TAG_ALL_DATA } else { 0x80 | number };
        if tlv.tag != expected || number > ALL_DATA as u32 {
            return Err(Deviation::NotAField(tlv.tag));
        }
        if let Some(after) = previous.filter(|&p| number <= p) {
            return Err(Deviation::OutOfOrder { field: number, after });
        }
        previous = Some(number);
        fields[number as usize] = Some(tlv.value);
    }
    let field = |n: usize| fields[n].unwrap_or(&[]);
    for (n, name) in [(GOCB_REF, "gocbRef"), (DAT_SET, "datSet"), (GO_ID, "goID")] {
        if field(n).len() > STRING_MAX || !visible(field(n)) {
            return Err(Deviation::NotVisibleString129(name));
        }
    }
    if field(GOCB_REF).is_empty() {
        return Err(Deviation::EmptyGocbRef);
    }
    if field(T).len() != 8 {
        return Err(Deviation::TimeSize(field(T).len()));
    }
    let counters =
        [(TAL, "timeAllowedtoLive"), (ST_NUM, "stNum"), (SQ_NUM, "sqNum"), (CONF_REV, "confRev"), (NUM_ENTRIES, "numDatSetEntries")];
    for (n, name) in counters {
        let v = field(n);
        if v.len() > U32_OCTETS || (v.len() == U32_OCTETS && v[0] != 0) {
            return Err(Deviation::Above32Bits(name));
        }
    }
    for (n, name) in [(SIMULATION, "simulation"), (NDS_COM, "ndsCom")] {
        if let Some(v) = fields[n].filter(|v| v.len() != 1) {
            return Err(Deviation::BooleanSize(name, v.len()));
        }
    }
    let Some(all_data) = fields[ALL_DATA] else { return Err(Deviation::NoAllData) };
    let present = ber::iter_tlvs(all_data).count();
    let declared = ber::decode_unsigned(field(NUM_ENTRIES)).unwrap_or(u64::MAX);
    if declared != present as u64 {
        return Err(Deviation::EntriesMismatch { declared, present });
    }
    check_strict_data(all_data)
}

/// Every Data of allData in preorder: one pass, stepping into structures
/// (decode_pdu checked that their members tile them).
fn check_strict_data(all_data: &[u8]) -> Result<(), Deviation> {
    let mut at = 0;
    while at < all_data.len() {
        let Ok(tlv) = ber::decode_tlv(all_data, at) else { return Ok(()) };
        let (tag, value) = (tlv.tag, tlv.value);
        let container = matches!(tag & 0x1F, 1 | 2); // array and structure: constructed, and only they
        if tag > 0xFF || tag & 0xC0 != 0x80 || tag & 0x1F == 0x1F || (tag & 0x20 != 0) != container {
            return Err(Deviation::NotAData(tag));
        }
        if container {
            at = tlv.end - value.len();
            continue;
        }
        let sizes: &[usize] = match tag {
            0x83 => &[1],
            0x87 => &[5, 9],
            0x8C => &[4, 6],
            0x91 => &[8],
            _ => &[],
        };
        if !sizes.is_empty() && !sizes.contains(&value.len()) {
            return Err(Deviation::DataSize(tag, value.len()));
        }
        if tag == 0x84 && value.first().is_none_or(|&u| u > 7) {
            return Err(Deviation::BitStringUnused);
        }
        if (tag == 0x85 || tag == 0x86) && value.is_empty() {
            return Err(Deviation::EmptyInteger);
        }
        if tag == 0x8A && !visible(value) {
            return Err(Deviation::DataNotVisible);
        }
        at = tlv.end;
    }
    Ok(())
}

/// The APPID header, refused when its Length leaves no room for a PDU.
fn goose_header(payload: &[u8]) -> Result<Header<'_>, DecodeError> {
    ethernet::parse_header(payload).filter(|h| !h.apdu.is_empty()).ok_or(DecodeError::Header)
}

/// As [`decode_pdu_strict`], from the APPID field.
pub fn decode_payload_strict(payload: &[u8]) -> Result<(Header<'_>, Received<'_>), DecodeError> {
    let header = goose_header(payload)?;
    Ok((header, decode_pdu_strict(header.apdu)?))
}

/// As [`decode_pdu_strict`], from an Ethernet frame (see [`decode_frame`]).
pub fn decode_frame_strict(raw: &[u8]) -> Result<Option<(Frame<'_>, Received<'_>)>, DecodeError> {
    match ethernet::parse_frame(raw, &[ETHERTYPE_GOOSE]) {
        None => Ok(None),
        Some(frame) if frame.header.apdu.is_empty() => Err(DecodeError::Header),
        Some(frame) => Ok(Some((frame, decode_pdu_strict(frame.header.apdu)?))),
    }
}

/// Decode from the APPID field, the bytes that follow the EtherType.
pub fn decode_payload(payload: &[u8]) -> Result<(Header<'_>, Received<'_>), DecodeError> {
    let header = goose_header(payload)?;
    Ok((header, decode_pdu(header.apdu)?))
}

/// Decode an Ethernet frame; `Ok(None)` when it is not a GOOSE frame (or
/// its Ethernet or APPID header is truncated), like
/// `open61850.goose.decode_goose_frame`.
pub fn decode_frame(raw: &[u8]) -> Result<Option<(Frame<'_>, Received<'_>)>, DecodeError> {
    match ethernet::parse_frame(raw, &[ETHERTYPE_GOOSE]) {
        None => Ok(None),
        Some(frame) if frame.header.apdu.is_empty() => Err(DecodeError::Header),
        Some(frame) => Ok(Some((frame, decode_pdu(frame.header.apdu)?))),
    }
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
    fn decodes_what_python_writes() {
        let (frame, message) = decode_frame(&FRAME).unwrap().unwrap();
        assert_eq!((frame.vlan_id, frame.header.app_id), (Some(5), 0x1000));
        assert_eq!((message.gocb_ref, message.go_id, message.st_num), (&b"IED01LD0/LLN0$GO"[..], Some(&b"G1"[..]), 128));
        assert_eq!(message.t, UtcTime { seconds: 1_767_225_600, fraction: 0x80_0000, quality: 0x0A });
        assert_eq!(message.entries, 2);
        let mut values = message.values();
        assert_eq!(values.next(), Some(Data::Boolean(true)));
        assert_eq!(values.next(), Some(Data::BitString { bits: &[0, 0], unused: 3 }));
        assert_eq!(values.next(), None);
        assert_eq!(decode_payload(&FRAME[18..]).map(|(_, m)| m), Ok(message));
    }

    #[test]
    fn strict_accepts_what_python_writes() {
        let apdu = &FRAME[26..];
        assert_eq!(decode_pdu_strict(apdu), decode_pdu(apdu));
        assert!(decode_frame_strict(&FRAME).unwrap().is_some());
    }

    #[test]
    fn strict_refusals() {
        let mut apdu = [0u8; 73];
        apdu[..72].copy_from_slice(&FRAME[26..]);
        let strict = |a: &[u8]| match decode_pdu_strict(a) {
            Err(DecodeError::NotConformant(d)) => Some(d),
            _ => None,
        };
        assert!(decode_pdu(&apdu).is_ok());
        assert_eq!(strict(&apdu), Some(Deviation::OctetsAfterPdu(1)));
        let mut entries = apdu;
        entries[61] = 0x03; // numDatSetEntries 2 -> 3
        assert_eq!(strict(&entries[..72]), Some(Deviation::EntriesMismatch { declared: 3, present: 2 }));
        let mut class = apdu;
        class[2] = 0xA0; // gocbRef as [0] constructed
        assert!(decode_pdu(&class[..72]).is_ok());
        assert_eq!(strict(&class[..72]), Some(Deviation::NotAField(0xA0)));
    }

    #[test]
    fn refusals() {
        let mut apdu = [0u8; 72];
        apdu.copy_from_slice(&FRAME[26..]);
        let mut no_st_num = apdu;
        no_st_num[43] = 0x8C; // stNum [5] becomes [12], which is skipped
        assert_eq!(decode_pdu(&no_st_num), Err(DecodeError::MissingField("stNum")));
        let mut broken = apdu;
        // The Quality 84 03 03 00 00 becomes a structure A2 03 whose member 83 05 runs past it.
        broken[67..72].copy_from_slice(&[0xA2, 0x03, 0x83, 0x05, 0x00]);
        assert!(matches!(decode_pdu(&broken), Err(DecodeError::AllData(BerError::Truncated { .. }))));
        // stNum 85 02 00 80 becomes 85 00: an empty counter, a field error.
        let mut empty_st_num = [0u8; 70];
        empty_st_num[..45].copy_from_slice(&apdu[..45]);
        empty_st_num[45..].copy_from_slice(&apdu[47..]);
        empty_st_num[1] = 0x44;
        empty_st_num[44] = 0x00;
        assert_eq!(decode_pdu(&empty_st_num), Err(DecodeError::EmptyCounter("stNum")));
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
