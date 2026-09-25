// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! Process bus codecs of open61850 for real-time paths.
//!
//! Each module mirrors the Python module of the same name in `open61850`
//! and accepts exactly the input it accepts: `tests/test_sv_decode_native.py`
//! compares both on random and mutated frames. Decoding borrows from the
//! input and allocates nothing; the crate is `no_std` and has no unsafe code.

#![no_std]
#![forbid(unsafe_code)]

pub mod ber;
pub mod ethernet;
pub mod sv;
pub mod time;
