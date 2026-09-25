# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Watch the GOOSE and SV streams of a process bus, from a capture file or live (Linux, root).

    python examples/supervise_bus.py capture.pcapng
    sudo python examples/supervise_bus.py --live eth1
"""

import argparse
import time

from open61850.pcap import read_pcap
from open61850.supervision import BusSupervisor, EventKind


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", help="a pcap/pcapng file, or an interface with --live")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    bus = BusSupervisor()
    if args.live:
        from open61850.capture import PacketCapture

        with PacketCapture(args.source, outgoing=False) as capture:
            try:
                while True:
                    frame = capture.recv()
                    for event in bus.check(time.time()) if frame is None else bus.feed(frame):
                        print(event)
            except KeyboardInterrupt:
                pass
    else:
        for frame in read_pcap(args.source):
            for event in bus.feed(frame):
                if event.kind is not EventKind.NEW_STREAM:
                    print(event)
    print("\n".join(bus.summary()))


if __name__ == "__main__":
    main()
