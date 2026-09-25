// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! MMS `Data` values (IEC 61850-8-1), written as `open61850.data.encode_data`
//! writes them.
//!
//! A sequence of values is flat, in preorder: a `Structure(n)` or `Array(n)`
//! is followed by its `n` members, each followed by its own members. The
//! values `[Structure(2), Boolean(true), BitString(..), Integer(3)]` are two
//! top-level values: a structure of a boolean and a bit string, then an
//! integer. Nothing is allocated and the caller's array is the whole tree.

use crate::ber::{self, BufferFull, Integer, Writer};
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
        Data::Raw { value, .. } => value.len(),
        Data::Structure(_) | Data::Array(_) => 0,
    })
}

/// Content length of the value at `items[i]` and the index after its members.
fn measure(items: &[Data<'_>], i: usize, depth: usize) -> Result<(usize, usize), DataError> {
    let item = items.get(i).ok_or(DataError::MissingMembers)?;
    match *item {
        Data::Structure(n) | Data::Array(n) => {
            if depth >= MAX_DEPTH {
                return Err(DataError::TooDeep);
            }
            let (mut content, mut next) = (0, i + 1);
            for _ in 0..n {
                let (len, after) = measure(items, next, depth + 1)?;
                content += ber::tlv_len(items[next].tag(), len);
                next = after;
            }
            Ok((content, next))
        }
        _ => Ok((leaf_len(item)?, i + 1)),
    }
}

/// Encoded length of a whole sequence (every top-level value as a TLV).
pub fn sequence_len(items: &[Data<'_>]) -> Result<usize, DataError> {
    let (mut total, mut i) = (0, 0);
    while i < items.len() {
        let (len, next) = measure(items, i, 0)?;
        total += ber::tlv_len(items[i].tag(), len);
        i = next;
    }
    Ok(total)
}

fn write_one(items: &[Data<'_>], i: usize, w: &mut Writer<'_>) -> Result<usize, DataError> {
    let item = &items[i];
    let (len, next) = measure(items, i, 0)?;
    w.put_header(item.tag(), len)?;
    match *item {
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
pub fn write_sequence(items: &[Data<'_>], w: &mut Writer<'_>) -> Result<(), DataError> {
    let mut i = 0;
    while i < items.len() {
        i = write_one(items, i, w)?;
    }
    Ok(())
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
    fn errors() {
        let mut buf = [0u8; 32];
        assert_eq!(encode(&[Data::Structure(2), Data::Boolean(true)], &mut buf), Err(DataError::MissingMembers));
        assert_eq!(encode(&[Data::Structure(usize::MAX)], &mut buf), Err(DataError::MissingMembers));
        assert_eq!(encode(&[Data::BitString { bits: &[0], unused: 8 }], &mut buf), Err(DataError::UnusedBits(8)));
        assert_eq!(encode(&[Data::Structure(1); MAX_DEPTH + 1], &mut buf), Err(DataError::TooDeep));
        assert_eq!(encode(&[Data::OctetString(&[0; 40])], &mut buf), Err(DataError::BufferFull));
    }
}
