// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Process bus codecs of open61850 for real-time paths.
//!
//! Each module mirrors the Python module of the same name in `open61850`
//! and accepts exactly the input it accepts (decoding) or writes the same
//! octets (encoding): `tests/test_sv_decode_native.py` and
//! `tests/test_goose_encode_native.py` compare both. Decoding borrows from
//! the input, encoding writes into the caller's buffer; nothing is
//! allocated, the crate is `no_std` and has no unsafe code.

#![no_std]
#![forbid(unsafe_code)]

pub mod ber;
pub mod data;
pub mod ethernet;
pub mod goose;
pub mod sv;
pub mod time;
