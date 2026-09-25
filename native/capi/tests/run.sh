#!/bin/sh
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0
#
# Build the C API, check that the committed header is the one cbindgen
# generates, then compile tests/test_capi.c against the static library
# (C11, warnings as errors, ASan and UBSan) and run it. Also compiles the
# header as C++. Needs cargo, cbindgen and a C/C++ compiler.

set -eu
cd "$(dirname "$0")/.."
cargo build --release -p open61850-c
target=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')

cbindgen --config cbindgen.toml --output "$target/open61850.h"
diff -u include/open61850.h "$target/open61850.h" || { echo "include/open61850.h is stale: regenerate it"; exit 1; }

${CC:-cc} -std=c11 -Wall -Wextra -Werror -pedantic -g -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include tests/test_capi.c "$target/release/libopen61850.a" -lpthread -ldl -lm -o "$target/test_capi"
"$target/test_capi"

echo '#include "open61850.h"' | ${CXX:-c++} -std=c++11 -Wall -Wextra -Werror -I include -x c++ -fsyntax-only -
