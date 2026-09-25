# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Publish a GOOSE control block taken from an SCL file, and send a trip after a few seconds.

    sudo python examples/goose_trip.py eth1 IED01.cid gcbTrip 02:00:00:00:00:01 [--after 3]

The data set's first member is set TRUE (the trip), every other member keeps its initial FALSE.
"""

import argparse
import time

from open61850 import scl
from open61850.data import BoolData
from open61850.goose_publisher import GoosePublisher


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("iface")
    parser.add_argument("scl_file")
    parser.add_argument("gocb", help="GSEControl name")
    parser.add_argument("src_mac")
    parser.add_argument("--after", type=float, default=3.0, help="seconds before the trip")
    args = parser.parse_args()

    ied = next(i for i in scl.load_ieds(args.scl_file) if any(g.name == args.gocb for g in i.goose_controls))
    block = next(g for g in ied.goose_controls if g.name == args.gocb)
    data_set = next(d for d in ied.data_sets if d.domain == block.domain and d.name == block.dat_set)
    values = [BoolData(False)] * len(data_set.members)
    with GoosePublisher(args.iface, block.goose_control(args.src_mac), values) as publisher:
        publisher.start()
        print(f"publishing {block.gocb_ref}, {len(values)} members")
        time.sleep(args.after)
        publisher.publish([BoolData(True)] + values[1:])
        print("trip sent")
        time.sleep(2)


if __name__ == "__main__":
    main()
