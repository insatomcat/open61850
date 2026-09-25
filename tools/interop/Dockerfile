# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0
#
# libiec61850's example servers and publishers, as peers for
# tests/test_interop_libiec61850.py. libiec61850 (GPL) is only run here,
# never linked to nor distributed with open61850.

FROM debian:bookworm-slim AS build
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc g++ make cmake git ca-certificates >/dev/null
ARG LIBIEC61850=v1.6.2.1
RUN git clone -q --depth 1 --branch "$LIBIEC61850" https://github.com/mz-automation/libiec61850 /l
RUN cmake -S /l -B /l/build -DBUILD_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release >/dev/null \
 && cmake --build /l/build -j"$(nproc)" >/dev/null
RUN mkdir /out && cp /l/build/examples/server_example_basic_io/server_example_basic_io \
    /l/build/examples/server_example_control/server_example_control \
    /l/build/examples/server_example_goose/server_example_goose \
    /l/build/examples/sv_publisher/sv_publisher_example /out/

FROM python:3.13-slim
COPY --from=build /out /usr/local/bin/
COPY --from=build /l/build/src/libiec61850.so* /usr/local/lib/
RUN ldconfig && pip install -q pytest
