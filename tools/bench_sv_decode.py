#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Cost of decoding SV frames with iec61850.sv, as the SV listener does it.

    python3 tools/bench_sv_decode.py [--asdus 2] [--rate 2400]

Builds a 6I3U frame (VLAN tagged, like rt_sender's), decodes it repeatedly
and prints the time per frame and the share of one core at ``--rate``
frames per second. On the dev Mac (Python 3.14, 2026-09-24): 9 us per
2-ASDU frame, about 2 % of a core at 2400 frames/s.
"""

from __future__ import annotations

import argparse
import struct
import sys
import timeit
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iec61850.sv import SvAsdu, SvPDU, decode_sv_frame, encode_sv_frame  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--asdus", type=int, default=2)
    parser.add_argument("--rate", type=int, default=2400, help="frames per second")
    parser.add_argument("--number", type=int, default=20000)
    args = parser.parse_args()

    sample = b"".join(struct.pack("!iI", i * 1000, 0) for i in range(9))
    pdu = SvPDU([SvAsdu("SV_1", n, 10000, 2, sample) for n in range(args.asdus)])
    frame = encode_sv_frame(
        pdu, dst_mac="01:0c:cd:04:00:01", src_mac="00:11:22:33:44:55", app_id=0x4000, vlan_id=100, vlan_priority=4
    )

    def decode() -> None:
        _, decoded = decode_sv_frame(frame)  # type: ignore[misc]
        for asdu in decoded.asdus:
            list(struct.iter_unpack("!iI", asdu.sample))

    per_frame = min(timeit.repeat(decode, number=args.number, repeat=5)) / args.number
    print(f"{len(frame)}-byte frame, {args.asdus} ASDU: {per_frame * 1e6:.1f} us/frame, "
          f"{per_frame * args.rate * 100:.2f} % of one core at {args.rate} frames/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
