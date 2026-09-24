# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""IEC 61850 protocol library (Apache-2.0).

Pure, dependency-free building blocks:

- :mod:`iec61850.ber`: BER (X.690) encoding and decoding primitives.
- :mod:`iec61850.data`: the MMS ``Data`` model shared by MMS, GOOSE and reports.
- :mod:`iec61850.ethernet`: Ethernet II / 802.1Q framing for GOOSE and SV.
- :mod:`iec61850.goose`: GOOSE PDU and frame codec (IEC 61850-8-1).
- :mod:`iec61850.sv`: Sampled Values PDU and frame codec (IEC 61850-9-2).

Nothing in this package opens sockets or captures traffic.
"""

__version__ = "0.1.0.dev0"
