// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! MMS UtcTime (IEC 61850-8-1), as `open61850.data.decode_utc_time` reads it.

/// Seconds since the UNIX epoch, fraction of second in 2^-24 units, TimeQuality octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UtcTime {
    pub seconds: u32,
    pub fraction: u32,
    pub quality: u8,
}

impl UtcTime {
    /// The first 8 octets of `raw`; `None` when there are fewer.
    pub fn decode(raw: &[u8]) -> Option<UtcTime> {
        match *raw.get(..8)? {
            [s0, s1, s2, s3, f0, f1, f2, quality] => Some(UtcTime {
                seconds: u32::from_be_bytes([s0, s1, s2, s3]),
                fraction: u32::from_be_bytes([0, f0, f1, f2]),
                quality,
            }),
            _ => None,
        }
    }
}
