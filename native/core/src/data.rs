// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! MMS `Data` values (IEC 61850-8-1), read and written as `open61850.data`
//! reads and writes them.
//!
//! A sequence of values is flat, in preorder: a `Structure(n)` or `Array(n)`
//! is followed by its `n` members, each followed by its own members. The
//! values `[Structure(2), Boolean(true), BitString(..), Integer(3)]` are two
//! top-level values: a structure of a boolean and a bit string, then an
//! integer. Nothing is allocated and the caller's array is the whole tree.
//!
//! Reading checks the TLV structure of every structure and array
//! ([`check_sequence`]) without recursion, so any nesting depth is safe,
//! then [`iter_sequence`] yields the values in the same preorder.

use crate::ber::{self, BerError, BufferFull, Integer, Writer};
use crate::time::UtcTime;

pub const TAG_ARRAY: u32 = 0xA1;
pub const TAG_STRUCTURE: u32 = 0xA2;
pub const TAG_BOOLEAN: u32 = 0x83;
pub const TAG_BIT_STRING: u32 = 0x84;
pub const TAG_INTEGER: u32 = 0x85;
pub const TAG_UNSIGNED: u32 = 0x86;
pub const TAG_FLOAT: u32 = 0x87;
pub const TAG_OCTET_STRING: u32 = 0x89;
pub const TAG_VISIBLE_STRING: u32 = 0x8A;
pub const TAG_BINARY_TIME: u32 = 0x8C;
pub const TAG_MMS_STRING: u32 = 0x8F;
pub const TAG_UTC_TIME: u32 = 0x91;

const FLOAT32_FORMAT: u8 = 0x08; // IEEE 754 single: 8 exponent bits
const FLOAT64_FORMAT: u8 = 0x0B; // IEEE 754 double: 11 exponent bits

/// Structures and arrays nest at most this deep.
pub const MAX_DEPTH: usize = 32;

/// One value of a preorder sequence.
///
/// Strings are the octets written on the wire: ASCII for a VisibleString,
/// UTF-8 for an MMSString.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Data<'a> {
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Float32(f32),
    Float64(f64),
    /// Bits packed MSB first; `unused` trailing bits of the last octet (0..7) are padding.
    BitString { bits: &'a [u8], unused: u8 },
    OctetString(&'a [u8]),
    VisibleString(&'a [u8]),
    MmsString(&'a [u8]),
    UtcTime(UtcTime),
    /// TimeOfDay with date: milliseconds since midnight (4 octets), days since 1984-01-01 (2).
    BinaryTime([u8; 6]),
    /// Followed by its members.
    Structure(usize),
    /// Followed by its elements.
    Array(usize),
    /// Any tag (the integer of its identifier octets) with its content octets.
    Raw { tag: u32, value: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataError {
    /// A structure or an array announces more members than the sequence holds.
    MissingMembers,
    /// Structures and arrays nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A bit string with more than 7 unused bits.
    UnusedBits(u8),
    BufferFull,
}

impl From<BufferFull> for DataError {
    fn from(_: BufferFull) -> Self {
        DataError::BufferFull
    }
}

impl Data<'_> {
    fn tag(&self) -> u32 {
        match *self {
            Data::Boolean(_) => TAG_BOOLEAN,
            Data::Integer(_) => TAG_INTEGER,
            Data::Unsigned(_) => TAG_UNSIGNED,
            Data::Float32(_) | Data::Float64(_) => TAG_FLOAT,
            Data::BitString { .. } => TAG_BIT_STRING,
            Data::OctetString(_) => TAG_OCTET_STRING,
            Data::VisibleString(_) => TAG_VISIBLE_STRING,
            Data::MmsString(_) => TAG_MMS_STRING,
            Data::UtcTime(_) => TAG_UTC_TIME,
            Data::BinaryTime(_) => TAG_BINARY_TIME,
            Data::Structure(_) => TAG_STRUCTURE,
            Data::Array(_) => TAG_ARRAY,
            Data::Raw { tag, .. } => tag,
        }
    }
}

/// Content octets of a value that has no members.
fn leaf_len(item: &Data<'_>) -> Result<usize, DataError> {
    Ok(match *item {
        Data::Boolean(_) => 1,
        Data::Integer(v) => Integer::signed(v).as_slice().len(),
        Data::Unsigned(v) => Integer::unsigned(v).as_slice().len(),
        Data::Float32(_) => 5,
        Data::Float64(_) => 9,
        Data::BitString { bits, unused } => {
            if unused > 7 {
                return Err(DataError::UnusedBits(unused));
            }
            1 + bits.len()
        }
        Data::OctetString(s) | Data::VisibleString(s) | Data::MmsString(s) => s.len(),
        Data::UtcTime(_) => 8,
        Data::BinaryTime(_) => 6,
        Data::Raw { value, .. } => value.len(),
        Data::Structure(_) | Data::Array(_) => 0,
    })
}

/// A preorder sequence read one value at a time: a slice or an array of
/// [`Data`], or a caller's own representation (the C API reads the caller's
/// array in place).
pub trait DataList<'a> {
    fn len(&self) -> usize;

    /// The value at `i`; `None` past the end, or when the caller's value is
    /// not a valid one (the encoder then reports [`DataError::MissingMembers`]).
    fn get(&self, i: usize) -> Option<Data<'a>>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> DataList<'a> for [Data<'a>] {
    fn len(&self) -> usize {
        <[Data<'a>]>::len(self)
    }

    fn get(&self, i: usize) -> Option<Data<'a>> {
        <[Data<'a>]>::get(self, i).copied()
    }
}

impl<'a, const N: usize> DataList<'a> for [Data<'a>; N] {
    fn len(&self) -> usize {
        N
    }

    fn get(&self, i: usize) -> Option<Data<'a>> {
        self.as_slice().get(i).copied()
    }
}

/// Tag and content length of the value at `items[i]`, and the index after its members.
fn measure<'a, L: DataList<'a> + ?Sized>(items: &L, i: usize, depth: usize) -> Result<(u32, usize, usize), DataError> {
    let item = items.get(i).ok_or(DataError::MissingMembers)?;
    match item {
        Data::Structure(n) | Data::Array(n) => {
            if depth >= MAX_DEPTH {
                return Err(DataError::TooDeep);
            }
            let (mut content, mut next) = (0, i + 1);
            for _ in 0..n {
                let (tag, len, after) = measure(items, next, depth + 1)?;
                content += ber::tlv_len(tag, len);
                next = after;
            }
            Ok((item.tag(), content, next))
        }
        _ => Ok((item.tag(), leaf_len(&item)?, i + 1)),
    }
}

/// Encoded length of a whole sequence (every top-level value as a TLV).
pub fn sequence_len<'a, L: DataList<'a> + ?Sized>(items: &L) -> Result<usize, DataError> {
    let (mut total, mut i) = (0, 0);
    while i < items.len() {
        let (tag, len, next) = measure(items, i, 0)?;
        total += ber::tlv_len(tag, len);
        i = next;
    }
    Ok(total)
}

fn write_one<'a, L: DataList<'a> + ?Sized>(items: &L, i: usize, w: &mut Writer<'_>) -> Result<usize, DataError> {
    let item = items.get(i).ok_or(DataError::MissingMembers)?;
    let (len, next) = match item {
        Data::Structure(_) | Data::Array(_) => {
            let (_, len, next) = measure(items, i, 0)?;
            (len, next)
        }
        _ => (leaf_len(&item)?, i + 1),
    };
    w.put_header(item.tag(), len)?;
    match item {
        Data::Boolean(v) => w.put(&[if v { 0xFF } else { 0x00 }])?,
        Data::Integer(v) => w.put(Integer::signed(v).as_slice())?,
        Data::Unsigned(v) => w.put(Integer::unsigned(v).as_slice())?,
        Data::Float32(v) => {
            w.put(&[FLOAT32_FORMAT])?;
            w.put(&v.to_be_bytes())?;
        }
        Data::Float64(v) => {
            w.put(&[FLOAT64_FORMAT])?;
            w.put(&v.to_be_bytes())?;
        }
        Data::BitString { bits, unused } => {
            w.put(&[unused])?;
            w.put(bits)?;
        }
        Data::OctetString(s) | Data::VisibleString(s) | Data::MmsString(s) => w.put(s)?,
        Data::UtcTime(t) => w.put(&t.encode())?,
        Data::BinaryTime(t) => w.put(&t)?,
        Data::Raw { value, .. } => w.put(value)?,
        Data::Structure(n) | Data::Array(n) => {
            let mut member = i + 1;
            for _ in 0..n {
                member = write_one(items, member, w)?;
            }
        }
    }
    Ok(next)
}

/// Write every top-level value of a sequence as a TLV.
pub fn write_sequence<'a, L: DataList<'a> + ?Sized>(items: &L, w: &mut Writer<'_>) -> Result<(), DataError> {
    let mut i = 0;
    while i < items.len() {
        i = write_one(items, i, w)?;
    }
    Ok(())
}

// --- reading ------------------------------------------------------------------

/// Number of TLVs tiling `content` exactly.
fn count_tlvs(content: &[u8]) -> Result<usize, BerError> {
    let mut n = 0;
    for tlv in ber::iter_tlvs(content) {
        tlv?;
        n += 1;
    }
    Ok(n)
}

/// Offset of the content of the TLV `tlv`.
fn content_start(tlv: &ber::Tlv<'_>) -> usize {
    tlv.end - tlv.value.len()
}

/// Check a sequence of `Data` TLVs as `open61850.data.decode_data_sequence`
/// does: the TLVs tile `content`, and so do the members of every structure
/// (0xA2) and array (0xA1), at any depth. Return the number of top-level values.
///
/// No recursion and no stack: each structure's members are checked on their
/// own, then one pass walks every value in preorder, stepping into the
/// structures. Once every structure is tiled by its members, the pass leaves
/// a structure exactly where its next sibling starts.
pub fn check_sequence(content: &[u8]) -> Result<usize, BerError> {
    let count = count_tlvs(content)?;
    let mut at = 0;
    while at < content.len() {
        let tlv = ber::decode_tlv(content, at)?;
        at = if tlv.tag == TAG_STRUCTURE || tlv.tag == TAG_ARRAY {
            count_tlvs(tlv.value)?;
            content_start(&tlv)
        } else {
            tlv.end
        };
    }
    Ok(count)
}

/// An INTEGER's value when it fits in 64 bits (empty content reads as 0).
fn signed(value: &[u8]) -> Option<i64> {
    let Some(&first) = value.first() else { return Some(0) };
    let fill = if first & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut v = value;
    while v.len() > 1 && v[0] == fill && (v[1] & 0x80) == (fill & 0x80) {
        v = &v[1..];
    }
    if v.len() > 8 {
        return None;
    }
    let mut octets = [fill; 8];
    octets[8 - v.len()..].copy_from_slice(v);
    Some(i64::from_be_bytes(octets))
}

/// One value from its tag and content octets, as `open61850.data.decode_data`
/// reads it; members of a structure or an array are the next values.
///
/// An INTEGER or unsigned value beyond 64 bits comes out as `Raw` (Python
/// keeps it as an int). A tag of more than four octets comes out as `Raw`
/// with tag `u32::MAX`.
pub fn decode_value<'a>(tag: u32, value: &'a [u8]) -> Result<Data<'a>, BerError> {
    Ok(match tag {
        TAG_BOOLEAN => Data::Boolean(value.first().is_some_and(|&b| b != 0)),
        TAG_BIT_STRING => Data::BitString { bits: value.get(1..).unwrap_or(&[]), unused: value.first().copied().unwrap_or(0) },
        TAG_INTEGER => match signed(value) {
            Some(v) => Data::Integer(v),
            None => Data::Raw { tag, value },
        },
        TAG_UNSIGNED => match ber::decode_unsigned(value) {
            Ok(v) => Data::Unsigned(v),
            Err(BerError::EmptyInteger) => Data::Unsigned(0),
            Err(_) => Data::Raw { tag, value },
        },
        TAG_FLOAT => match *value {
            [_, a, b, c, d] => Data::Float32(f32::from_be_bytes([a, b, c, d])),
            [_, a, b, c, d, e, f, g, h] => Data::Float64(f64::from_be_bytes([a, b, c, d, e, f, g, h])),
            _ => Data::Raw { tag, value },
        },
        TAG_OCTET_STRING => Data::OctetString(value),
        // IA5String and [0] VisibleString variants seen in the field.
        TAG_VISIBLE_STRING | 0x1A | 0x80 => Data::VisibleString(value),
        TAG_BINARY_TIME => match *value {
            [a, b, c, d, e, f] => Data::BinaryTime([a, b, c, d, e, f]),
            _ => Data::Raw { tag, value },
        },
        TAG_MMS_STRING => Data::MmsString(value),
        TAG_UTC_TIME => match UtcTime::decode(value) {
            Some(t) => Data::UtcTime(t),
            None => Data::Raw { tag, value },
        },
        TAG_ARRAY => Data::Array(count_tlvs(value)?),
        TAG_STRUCTURE => Data::Structure(count_tlvs(value)?),
        _ => Data::Raw { tag, value },
    })
}

/// The values of a sequence accepted by [`check_sequence`], in preorder.
pub fn iter_sequence(content: &[u8]) -> Values<'_> {
    Values { content, at: 0 }
}

/// Iterator over the values of a checked sequence; it stops at the first
/// malformed TLV, which [`check_sequence`] would have refused.
#[derive(Debug, Clone)]
pub struct Values<'a> {
    content: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Values<'a> {
    type Item = Data<'a>;

    fn next(&mut self) -> Option<Data<'a>> {
        if self.at >= self.content.len() {
            return None;
        }
        let item = ber::decode_tlv(self.content, self.at).and_then(|tlv| Ok((tlv, decode_value(tlv.tag, tlv.value)?)));
        match item {
            Ok((tlv, value)) => {
                self.at = if matches!(value, Data::Structure(_) | Data::Array(_)) { content_start(&tlv) } else { tlv.end };
                Some(value)
            }
            Err(_) => {
                self.at = self.content.len();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<'b>(items: &[Data<'_>], buf: &'b mut [u8]) -> Result<&'b [u8], DataError> {
        let n = sequence_len(items)?;
        write_sequence(items, &mut Writer::new(buf))?;
        Ok(&buf[..n])
    }

    #[test]
    fn nested_values() {
        let items = [
            Data::Structure(2),
            Data::Boolean(true),
            Data::BitString { bits: &[0x00, 0x00], unused: 3 },
            Data::Array(0),
            Data::Unsigned(0x80),
        ];
        let mut buf = [0u8; 32];
        assert_eq!(
            encode(&items, &mut buf).unwrap(),
            &[0xA2, 0x08, 0x83, 0x01, 0xFF, 0x84, 0x03, 0x03, 0x00, 0x00, 0xA1, 0x00, 0x86, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn reads_what_it_writes() {
        let items = [
            Data::Structure(3),
            Data::Integer(-129),
            Data::Array(1),
            Data::Structure(0),
            Data::BinaryTime([0, 0, 0, 1, 0, 2]),
            Data::Unsigned(u64::MAX),
            Data::Float32(1.5),
        ];
        let mut buf = [0u8; 64];
        let n = sequence_len(&items).unwrap();
        write_sequence(&items, &mut Writer::new(&mut buf)).unwrap();
        assert_eq!(check_sequence(&buf[..n]), Ok(3));
        let mut read = iter_sequence(&buf[..n]);
        for item in items {
            assert_eq!(read.next(), Some(item));
        }
        assert_eq!(read.next(), None);
    }

    #[test]
    fn integers_as_python_reads_them() {
        let cases: [(&[u8], Option<i64>); 8] = [
            (&[], Some(0)),
            (&[0xFF], Some(-1)),
            (&[0x00, 0x80], Some(128)),
            (&[0xFF, 0xFF, 0x7F], Some(-129)),
            (&[0; 20], Some(0)),
            (&[0xFF; 20], Some(-1)),
            (&[0x00, 0x80, 0, 0, 0, 0, 0, 0, 0], None),
            (&[0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], None),
        ];
        for (octets, expected) in cases {
            assert_eq!(signed(octets), expected, "{octets:02X?}");
        }
    }

    #[test]
    fn deep_nesting_is_checked_without_recursion() {
        // 10,000 structures, each holding the next.
        const DEPTH: usize = 10_000;
        let mut content = [0usize; DEPTH]; // content length of each level, outermost first
        for level in (0..DEPTH - 1).rev() {
            let inner = content[level + 1];
            content[level] = ber::tlv_len(TAG_STRUCTURE, inner);
        }
        let mut buf = [0u8; 40_000];
        let mut w = Writer::new(&mut buf);
        for len in content {
            w.put_header(TAG_STRUCTURE, len).unwrap();
        }
        let n = w.position();
        assert_eq!(check_sequence(&buf[..n]), Ok(1));
        assert_eq!(iter_sequence(&buf[..n]).count(), DEPTH);
        buf[n - 1] = 1; // the innermost structure now runs past its parent
        assert!(check_sequence(&buf[..n]).is_err());
    }

    #[test]
    fn errors() {
        let mut buf = [0u8; 32];
        assert_eq!(encode(&[Data::Structure(2), Data::Boolean(true)], &mut buf), Err(DataError::MissingMembers));
        assert_eq!(encode(&[Data::Structure(usize::MAX)], &mut buf), Err(DataError::MissingMembers));
        assert_eq!(encode(&[Data::BitString { bits: &[0], unused: 8 }], &mut buf), Err(DataError::UnusedBits(8)));
        assert_eq!(encode(&[Data::Structure(1); MAX_DEPTH + 1], &mut buf), Err(DataError::TooDeep));
        assert_eq!(encode(&[Data::OctetString(&[0; 40])], &mut buf), Err(DataError::BufferFull));
    }
}
