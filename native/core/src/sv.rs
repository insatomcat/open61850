// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Sampled Values decoding (IEC 61850-9-2, IEC 61869-9), as `open61850.sv`
//! does it: same fields, same checks, same accepted input.
//!
//! ```text
//! SavPdu ::= [APPLICATION 0] IMPLICIT SEQUENCE {
//!     noASDU [0] IMPLICIT INTEGER, security [1] ANY OPTIONAL,
//!     asdu   [2] IMPLICIT SEQUENCE OF ASDU }
//! ASDU ::= SEQUENCE { svID [0], datSet [1] OPTIONAL, smpCnt [2], confRev [3],
//!     refrTm [4] OPTIONAL, smpSynch [5], smpRate [6] OPTIONAL, sample [7],
//!     smpMod [8] OPTIONAL, gmIdentity [9] OPTIONAL }
//! ```
//!
//! [`decode_pdu`] checks the whole PDU (every ASDU, noASDU) before returning;
//! [`SvPdu::asdus`] then walks the ASDUs again without allocating.

use core::fmt;

use crate::ber::{self, BerError};
use crate::ethernet::{self, Frame, Header};
use crate::time::UtcTime;

pub const TAG_SAV_PDU: u32 = 0x60;
const TAG_NO_ASDU: u32 = 0x80;
const TAG_SECURITY: u32 = 0xA1;
const TAG_SEQ_ASDU: u32 = 0xA2;
const TAG_ASDU: u32 = 0x30;

pub const SMP_SYNCH_NONE: u8 = 0;
pub const SMP_SYNCH_LOCAL: u8 = 1;
pub const SMP_SYNCH_GLOBAL: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvError {
    Ber(BerError),
    /// The bytes after the EtherType are too short, or their Length is inconsistent.
    Header,
    UnexpectedTag { expected: u32, found: u32 },
    MissingField(&'static str),
    BadSize { field: &'static str, size: usize, got: usize },
    MissingNoAsdu,
    /// noASDU does not match the ASDUs present (`declared` is `None` above 64 bits).
    NoAsduMismatch { declared: Option<u64>, present: usize },
    /// A sample buffer whose length is not a multiple of 8.
    SampleLength(usize),
}

impl From<BerError> for SvError {
    fn from(e: BerError) -> Self {
        SvError::Ber(e)
    }
}

impl fmt::Display for SvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SvError::Ber(e) => e.fmt(f),
            SvError::Header => f.write_str("SV header too short or with an inconsistent Length"),
            SvError::UnexpectedTag { expected, found } => write!(f, "expected tag 0x{expected:X}, found 0x{found:X}"),
            SvError::MissingField(name) => write!(f, "ASDU without {name}"),
            SvError::BadSize { field, size, got } => write!(f, "{field} must be {size} bytes, got {got}"),
            SvError::MissingNoAsdu => f.write_str("SavPdu without noASDU"),
            SvError::NoAsduMismatch { declared: Some(n), present } => {
                write!(f, "noASDU={n} but {present} ASDUs present")
            }
            SvError::NoAsduMismatch { declared: None, present } => {
                write!(f, "noASDU above 64 bits but {present} ASDUs present")
            }
            SvError::SampleLength(n) => write!(f, "sample length {n} is not a multiple of 8"),
        }
    }
}

/// One ASDU; the strings and buffers point into the decoded bytes.
///
/// `sv_id` and `dat_set` are raw VisibleString octets. `gm_identity` has the
/// length it came with (8 in a conformant stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Asdu<'a> {
    pub sv_id: &'a [u8],
    pub dat_set: Option<&'a [u8]>,
    pub smp_cnt: u16,
    pub conf_rev: u32,
    pub refr_tm: Option<UtcTime>,
    pub smp_synch: u8,
    pub smp_rate: Option<u16>,
    pub sample: &'a [u8],
    pub smp_mod: Option<u16>,
    pub gm_identity: Option<&'a [u8]>,
}

fn fixed(content: &[u8], size: usize, field: &'static str) -> Result<u32, SvError> {
    if content.len() != size {
        return Err(SvError::BadSize { field, size, got: content.len() });
    }
    Ok(content.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

fn decode_asdu(content: &[u8]) -> Result<Asdu<'_>, SvError> {
    // Context tags [0]..[9] (0x80..0x89); the last occurrence wins, other tags are skipped.
    let mut fields: [Option<&[u8]>; 10] = [None; 10];
    for tlv in ber::iter_tlvs(content) {
        let tlv = tlv?;
        if let Some(slot) = tlv.tag.checked_sub(0x80).and_then(|n| fields.get_mut(n as usize)) {
            *slot = Some(tlv.value);
        }
    }
    let required = |n: usize, name: &'static str| fields[n].ok_or(SvError::MissingField(name));
    let sv_id = required(0, "svID")?;
    let smp_cnt = required(2, "smpCnt")?;
    let conf_rev = required(3, "confRev")?;
    let smp_synch = required(5, "smpSynch")?;
    let sample = required(7, "sample")?;
    let refr_tm = match fields[4] {
        Some(raw) => Some(UtcTime::decode(raw).ok_or(SvError::Ber(BerError::Truncated {
            tag: 0x84,
            needed: 8,
            left: raw.len(),
        }))?),
        None => None,
    };
    Ok(Asdu {
        sv_id,
        dat_set: fields[1],
        smp_cnt: fixed(smp_cnt, 2, "smpCnt")? as u16,
        conf_rev: fixed(conf_rev, 4, "confRev")?,
        refr_tm,
        smp_synch: fixed(smp_synch, 1, "smpSynch")? as u8,
        smp_rate: fields[6].map(|c| fixed(c, 2, "smpRate")).transpose()?.map(|v| v as u16),
        sample,
        smp_mod: fields[8].map(|c| fixed(c, 2, "smpMod")).transpose()?.map(|v| v as u16),
        gm_identity: fields[9],
    })
}

/// A checked `SavPdu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvPdu<'a> {
    pub security: Option<&'a [u8]>,
    count: usize,
    content: &'a [u8],
}

impl<'a> SvPdu<'a> {
    /// Number of ASDUs (noASDU).
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The ASDUs in order, across every seqASDU.
    pub fn asdus(&self) -> Asdus<'a> {
        Asdus { outer: ber::iter_tlvs(self.content), inner: None }
    }
}

/// Iterator over the ASDUs of a checked [`SvPdu`].
#[derive(Debug, Clone)]
pub struct Asdus<'a> {
    outer: ber::Tlvs<'a>,
    inner: Option<ber::Tlvs<'a>>,
}

impl<'a> Iterator for Asdus<'a> {
    type Item = Asdu<'a>;

    fn next(&mut self) -> Option<Asdu<'a>> {
        loop {
            if let Some(inner) = &mut self.inner {
                match inner.next() {
                    // Checked by decode_pdu: neither can fail here.
                    Some(item) => return item.ok().and_then(|t| decode_asdu(t.value).ok()),
                    None => self.inner = None,
                }
            }
            let tlv = self.outer.next()?.ok()?;
            if tlv.tag == TAG_SEQ_ASDU {
                self.inner = Some(ber::iter_tlvs(tlv.value));
            }
        }
    }
}

/// Decode and check a `SavPdu` (the bytes after the 8-byte APPID header).
///
/// Bytes after the `SavPdu` TLV are ignored.
pub fn decode_pdu(apdu: &[u8]) -> Result<SvPdu<'_>, SvError> {
    let outer = ber::decode_tlv(apdu, 0)?;
    if outer.tag != TAG_SAV_PDU {
        return Err(SvError::UnexpectedTag { expected: TAG_SAV_PDU, found: outer.tag });
    }
    let mut no_asdu: Option<&[u8]> = None;
    let mut security = None;
    let mut count = 0usize;
    for tlv in ber::iter_tlvs(outer.value) {
        let tlv = tlv?;
        match tlv.tag {
            TAG_NO_ASDU => {
                if tlv.value.is_empty() {
                    return Err(BerError::EmptyInteger.into());
                }
                no_asdu = Some(tlv.value);
            }
            TAG_SECURITY => security = Some(tlv.value),
            TAG_SEQ_ASDU => {
                for item in ber::iter_tlvs(tlv.value) {
                    let item = item?;
                    if item.tag != TAG_ASDU {
                        return Err(SvError::UnexpectedTag { expected: TAG_ASDU, found: item.tag });
                    }
                    decode_asdu(item.value)?;
                    count += 1;
                }
            }
            _ => {}
        }
    }
    let declared = ber::decode_unsigned(no_asdu.ok_or(SvError::MissingNoAsdu)?).ok();
    if declared != Some(count as u64) {
        return Err(SvError::NoAsduMismatch { declared, present: count });
    }
    Ok(SvPdu { security, count, content: outer.value })
}

/// Decode from the APPID field, the bytes that follow the EtherType.
pub fn decode_payload(payload: &[u8]) -> Result<(Header<'_>, SvPdu<'_>), SvError> {
    let header = ethernet::parse_header(payload).ok_or(SvError::Header)?;
    Ok((header, decode_pdu(header.apdu)?))
}

/// Decode an Ethernet frame; `Ok(None)` when it is not an SV frame (or its
/// Ethernet or APPID header is truncated), like `open61850.sv.decode_sv_frame`.
pub fn decode_frame(raw: &[u8]) -> Result<Option<(Frame<'_>, SvPdu<'_>)>, SvError> {
    match ethernet::parse_frame(raw, &[ethernet::ETHERTYPE_SV]) {
        None => Ok(None),
        Some(frame) => Ok(Some((frame, decode_pdu(frame.header.apdu)?))),
    }
}

/// `(value, quality)` pairs of INT32 and 32-bit quality (9-2LE, IEC 61869-9).
pub fn int32_samples(sample: &[u8]) -> Result<impl Iterator<Item = (i32, u32)> + '_, SvError> {
    if !sample.len().is_multiple_of(8) {
        return Err(SvError::SampleLength(sample.len()));
    }
    Ok(sample.as_chunks::<8>().0.iter().map(|&[v0, v1, v2, v3, q0, q1, q2, q3]| {
        (i32::from_be_bytes([v0, v1, v2, v3]), u32::from_be_bytes([q0, q1, q2, q3]))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two ASDUs (svID "SV", smpCnt 1 and 2, confRev 1, smpSynch 2, one
    // INT32 channel each) and two padding octets, from open61850.sv.encode_sv_pdu.
    const PDU: [u8; 67] = [
        0x60, 0x3F, 0x80, 0x01, 0x02, 0xA2, 0x3A, //
        0x30, 0x1B, 0x80, 0x02, 0x53, 0x56, 0x82, 0x02, 0x00, 0x01, 0x83, 0x04, 0x00, 0x00, 0x00, 0x01, 0x85, 0x01,
        0x02, 0x87, 0x08, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x20, 0x00, //
        0x30, 0x1B, 0x80, 0x02, 0x53, 0x56, 0x82, 0x02, 0x00, 0x02, 0x83, 0x04, 0x00, 0x00, 0x00, 0x01, 0x85, 0x01,
        0x02, 0x87, 0x08, 0x08, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, //
        0x00, 0x00,
    ];

    #[test]
    fn decodes_both_asdus() {
        let raw = PDU;
        let pdu = decode_pdu(&raw).unwrap();
        assert_eq!(pdu.len(), 2);
        let asdus: [Asdu; 2] = {
            let mut it = pdu.asdus();
            [it.next().unwrap(), it.next().unwrap()]
        };
        assert_eq!((asdus[0].sv_id, asdus[0].smp_cnt, asdus[0].conf_rev, asdus[0].smp_synch), (&b"SV"[..], 1, 1, 2));
        assert_eq!(asdus[1].smp_cnt, 2);
        let mut samples = int32_samples(asdus[0].sample).unwrap();
        assert_eq!(samples.next(), Some((-2, 0x2000)));
        assert_eq!(int32_samples(asdus[1].sample).unwrap().next(), Some((0x0800_0000, 0x0700_0000)));
    }

    #[test]
    fn refuses_a_wrong_count() {
        let mut raw = PDU;
        raw[4] = 3;
        assert_eq!(decode_pdu(&raw), Err(SvError::NoAsduMismatch { declared: Some(3), present: 2 }));
    }

    #[test]
    fn refuses_a_missing_field() {
        let mut raw = PDU;
        raw[13] = 0x8A; // smpCnt of the first ASDU becomes [10], which is skipped
        assert_eq!(decode_pdu(&raw), Err(SvError::MissingField("smpCnt")));
    }
}
