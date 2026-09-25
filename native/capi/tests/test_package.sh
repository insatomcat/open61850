#!/bin/sh
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0
#
# test_package.sh TARBALL: unpack a libopen61850 package, then build
# tests/test_capi.c against it through pkg-config, statically and against
# the shared library, and run both. Needs a C compiler and pkg-config.

set -eu
tarball=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
tests=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -C "$work" -xzf "$tarball"
root=$(echo "$work"/libopen61850-*)
export PKG_CONFIG_PATH="$root/lib/pkgconfig"

echo "static: $(pkg-config --libs open61850-static)"
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror $(pkg-config --cflags open61850-static) "$tests/test_capi.c" \
    $(pkg-config --libs open61850-static) -o "$work/test_static"
"$work/test_static"

echo "shared: $(pkg-config --libs open61850)"
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror $(pkg-config --cflags open61850) "$tests/test_capi.c" \
    $(pkg-config --libs open61850) -o "$work/test_shared"
LD_LIBRARY_PATH="$root/lib" "$work/test_shared"
soname=$(readelf -d "$root/lib/libopen61850.so" | sed -n 's/.*SONAME.*\[\(.*\)\]/\1/p')
needed=$(readelf -d "$work/test_shared" | grep -c "Shared library: \[$soname\]")
[ "$needed" = 1 ] || { echo "the program does not need $soname"; exit 1; }
echo "shared: linked against $soname"
