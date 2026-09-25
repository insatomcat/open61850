#!/bin/sh
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0
#
# package.sh OUTDIR: build libopen61850 (release) and write
# OUTDIR/libopen61850-VERSION-ARCH-linux-gnu.tar.gz:
#   include/open61850.h
#   lib/libopen61850.a, lib/libopen61850.so.VERSION and its soname links
#   lib/pkgconfig/open61850.pc (shared) and open61850-static.pc
#   README.md, LICENSE
# The release workflow runs it in manylinux2014 (glibc 2.17).

set -eu
mkdir -p "$1"
out=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
major=${version%%.*}
minor=${version#*.}; minor=${minor%%.*}
if [ "$major" = 0 ]; then abi="0.$minor"; else abi=$major; fi
arch=$(uname -m)
name="libopen61850-$version-$arch-linux-gnu"

# The system libraries the static library needs, as rustc reports them.
touch capi/src/lib.rs
native=$(cargo rustc -q --release -p open61850-c --crate-type staticlib -- --print native-static-libs 2>&1 \
         | sed -n 's/.*native-static-libs: //p' | tail -1)
cargo build -q --release -p open61850-c
target=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')

stage=$(mktemp -d)
root="$stage/$name"
mkdir -p "$root/include" "$root/lib/pkgconfig"
cp capi/include/open61850.h "$root/include/"
cp "$target/release/libopen61850.a" "$root/lib/"
cp "$target/release/libopen61850.so" "$root/lib/libopen61850.so.$version"
ln -s "libopen61850.so.$version" "$root/lib/libopen61850.so.$abi"
ln -s "libopen61850.so.$abi" "$root/lib/libopen61850.so"
cp capi/README.md "$root/"
cp LICENSE "$root/"

pc_head='prefix=${pcfiledir}/../..
includedir=${prefix}/include
libdir=${prefix}/lib
'
cat > "$root/lib/pkgconfig/open61850.pc" <<PC
$pc_head
Name: open61850
Description: IEC 61850 process bus codecs: Sampled Values decoding, GOOSE encoding and decoding
Version: $version
URL: https://github.com/insatomcat/open61850
Cflags: -I\${includedir}
Libs: -L\${libdir} -lopen61850
PC
cat > "$root/lib/pkgconfig/open61850-static.pc" <<PC
$pc_head
Name: open61850-static
Description: IEC 61850 process bus codecs, linked statically
Version: $version
URL: https://github.com/insatomcat/open61850
Cflags: -I\${includedir}
Libs: \${libdir}/libopen61850.a $native
PC

tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
rm -rf "$stage"
echo "$out/$name.tar.gz (soname libopen61850.so.$abi, static needs: $native)"
