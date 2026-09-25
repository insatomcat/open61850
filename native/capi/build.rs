// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0

//! The shared library's soname: libopen61850.so.0.MINOR while the version is
//! 0.x (each minor version may change the ABI), libopen61850.so.MAJOR after.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        let major = std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap();
        let minor = std::env::var("CARGO_PKG_VERSION_MINOR").unwrap();
        let abi = if major == "0" { format!("0.{minor}") } else { major };
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libopen61850.so.{abi}");
    }
}
