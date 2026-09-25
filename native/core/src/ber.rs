// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! X.690 BER reading, as `open61850.ber` does it.
//!
//! A tag is the integer of its identifier octets (`0x83`, `0xBF48`); tags of
//! more than four octets read as `u32::MAX`. Lengths are definite, short or
//! long form (non-minimal long forms accepted).

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    MissingTag,
    TruncatedTag,
    MissingLength,
    IndefiniteLength,
    TruncatedLength,
    /// The content runs past the end of the enclosing data.
    Truncated { tag: u32, needed: usize, left: usize },
    EmptyInteger,
    /// An unsigned INTEGER above `u64::MAX`.
    IntegerTooLarge,
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BerError::MissingTag => f.write_str("missing tag"),
            BerError::TruncatedTag => f.write_str("truncated high-number tag"),
            BerError::MissingLength => f.write_str("missing length"),
            BerError::IndefiniteLength => f.write_str("indefinite length is not supported"),
            BerError::TruncatedLength => f.write_str("truncated long-form length"),
            BerError::Truncated { tag, needed, left } => {
                write!(f, "TLV 0x{tag:X} truncated: needs {needed} bytes, {left} left")
            }
            BerError::EmptyInteger => f.write_str("empty INTEGER"),
            BerError::IntegerTooLarge => f.write_str("INTEGER above 64 bits"),
        }
    }
}

/// One decoded TLV: tag, content octets and the offset right after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
    pub end: usize,
}

/// Return `(tag, next_offset)`.
pub fn decode_tag(data: &[u8], offset: usize) -> Result<(u32, usize), BerError> {
    let first = *data.get(offset).ok_or(BerError::MissingTag)?;
    let mut tag = u32::from(first);
    let mut at = offset + 1;
    if first & 0x1F == 0x1F {
        loop {
            let b = *data.get(at).ok_or(BerError::TruncatedTag)?;
            at += 1;
            tag = if tag > 0x00FF_FFFF { u32::MAX } else { (tag << 8) | u32::from(b) };
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((tag, at))
}

/// Return `(length, next_offset)`; a length beyond `usize` reads as `usize::MAX`.
pub fn decode_length(data: &[u8], offset: usize) -> Result<(usize, usize), BerError> {
    let first = *data.get(offset).ok_or(BerError::MissingLength)?;
    if first < 0x80 {
        return Ok((usize::from(first), offset + 1));
    }
    let n = usize::from(first & 0x7F);
    if n == 0 {
        return Err(BerError::IndefiniteLength);
    }
    let bytes = data.get(offset + 1..offset + 1 + n).ok_or(BerError::TruncatedLength)?;
    let length = bytes.iter().fold(0usize, |acc, &b| acc.saturating_mul(256).saturating_add(usize::from(b)));
    Ok((length, offset + 1 + n))
}

/// Decode the TLV at `offset`; its content must lie within `data`.
pub fn decode_tlv(data: &[u8], offset: usize) -> Result<Tlv<'_>, BerError> {
    // Fast path for a low tag number and a short length, the usual case on the
    // process bus.
    let (tag, start, length) = match data.get(offset..).and_then(|d| d.get(..2)) {
        Some(&[t, l]) if t & 0x1F != 0x1F && l < 0x80 => (u32::from(t), offset + 2, usize::from(l)),
        _ => {
            let (tag, at) = decode_tag(data, offset)?;
            let (length, at) = decode_length(data, at)?;
            (tag, at, length)
        }
    };
    let left = data.len() - start;
    if length > left {
        return Err(BerError::Truncated { tag, needed: length, left });
    }
    Ok(Tlv { tag, value: &data[start..start + length], end: start + length })
}

/// Consecutive TLVs covering exactly `data`; iteration stops after an error.
pub fn iter_tlvs(data: &[u8]) -> Tlvs<'_> {
    Tlvs { data, offset: 0 }
}

#[derive(Debug, Clone)]
pub struct Tlvs<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = Result<Tlv<'a>, BerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let tlv = decode_tlv(self.data, self.offset);
        self.offset = match tlv {
            Ok(t) => t.end,
            Err(_) => self.data.len(),
        };
        Some(tlv)
    }
}

/// Lenient unsigned INTEGER: the conformant form (leading `00` when the high
/// bit is set) and the common one without it.
pub fn decode_unsigned(content: &[u8]) -> Result<u64, BerError> {
    if content.is_empty() {
        return Err(BerError::EmptyInteger);
    }
    let first = content.iter().position(|&b| b != 0).unwrap_or(content.len());
    let significant = &content[first..];
    if significant.len() > 8 {
        return Err(BerError::IntegerTooLarge);
    }
    Ok(significant.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_forms() {
        let t = decode_tlv(&[0x80, 0x01, 0x05], 0).unwrap();
        assert_eq!((t.tag, t.value, t.end), (0x80, &[5u8][..], 3));
        let t = decode_tlv(&[0x80, 0x82, 0x00, 0x01, 0x07], 0).unwrap();
        assert_eq!((t.tag, t.value), (0x80, &[7u8][..]));
        let t = decode_tlv(&[0xBF, 0x81, 0x48, 0x00], 0).unwrap();
        assert_eq!((t.tag, t.value.len()), (0xBF8148, 0));
    }

    #[test]
    fn errors() {
        assert_eq!(decode_tlv(&[0x80], 0), Err(BerError::MissingLength));
        assert_eq!(decode_tlv(&[0x80, 0x80], 0), Err(BerError::IndefiniteLength));
        assert_eq!(decode_tlv(&[0x80, 0x82, 0x00], 0), Err(BerError::TruncatedLength));
        assert_eq!(decode_tlv(&[0x9F, 0x81], 0), Err(BerError::TruncatedTag));
        assert_eq!(decode_tlv(&[0x80, 0x02, 0x00], 0), Err(BerError::Truncated { tag: 0x80, needed: 2, left: 1 }));
        let huge = [0x80, 0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(decode_tlv(&huge, 0), Err(BerError::Truncated { .. })));
    }

    #[test]
    fn unsigned() {
        assert_eq!(decode_unsigned(&[0x00, 0x80]), Ok(0x80));
        assert_eq!(decode_unsigned(&[0x80]), Ok(0x80));
        assert_eq!(decode_unsigned(&[0; 20]), Ok(0));
        assert_eq!(decode_unsigned(&[]), Err(BerError::EmptyInteger));
        assert_eq!(decode_unsigned(&[1; 9]), Err(BerError::IntegerTooLarge));
    }
}
