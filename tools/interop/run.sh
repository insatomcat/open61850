#!/bin/sh
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0
#
# Run the interoperability tests against libiec61850 in Docker:
#   tools/interop/run.sh [pytest arguments]
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
docker build -q -t open61850-interop "$root/tools/interop" >/dev/null
# --privileged: raw sockets and promiscuous mode on lo for GOOSE and SV.
exec docker run --rm --privileged -v "$root":/src -w /src open61850-interop \
    python -m pytest -p no:cacheprovider tests/test_interop_libiec61850.py "$@"
