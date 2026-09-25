#!/bin/sh
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0
#
# package-manylinux.sh OUTDIR: run package.sh in manylinux2014 for this
# machine's architecture (glibc 2.17, so the package works on any later
# distribution), then test the package there. Needs Docker.

set -eu
mkdir -p "$1"
out=$(cd "$1" && pwd)
repo=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(uname -m)
[ "$arch" = arm64 ] && arch=aarch64  # macOS
docker run --rm -v "$repo":/src:ro -v "$out":/out "quay.io/pypa/manylinux2014_$arch" sh -ec '
    cp -r /src/native /w && rm -rf /w/target
    curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
    . "$HOME/.cargo/env"
    /w/capi/package.sh /out
    /w/capi/tests/test_package.sh /out/libopen61850-*.tar.gz
'
