# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Enable a report control block, print its reports for a while, then release it.

    python examples/subscribe_reports.py 192.0.2.10 'IED01_LD0/LLN0$BR$CB_MEAS' [--seconds 10]

The block may be given without its instance number: a free instance is taken.
"""

import argparse
import queue
import time

from open61850.mms import MmsClient, ObjectName, decode_report, is_report, rcb, to_object_name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host")
    parser.add_argument("block", help="LD/LLN0$BR$Name or LD/LLN0$RP$Name, with or without instance number")
    parser.add_argument("--port", type=int, default=102)
    parser.add_argument("--seconds", type=float, default=10.0)
    args = parser.parse_args()

    target = to_object_name(args.block)
    reports: queue.Queue = queue.Queue()
    with MmsClient.connect(args.host, args.port, on_information_report=reports.put) as client:
        names = client.get_name_list(0, target.domain)  # named variables of the logical device
        blocks = [ObjectName(n, target.domain) for n in names if rcb.is_rcb_name(n)]
        candidates = [b for b in blocks if b.item == target.item or rcb.instance_base(b.item) == target.item]
        free = rcb.find_free(client, candidates)
        if free is None:
            raise SystemExit(f"no free instance of {args.block}")
        rcb.enable(client, free.rcb, rcb.RcbSettings(intg_pd_ms=2000))
        print(f"enabled {free.rcb} (data set {free.dat_set})")
        try:
            end = time.monotonic() + args.seconds
            while time.monotonic() < end:
                try:
                    message = reports.get(timeout=0.5)
                except queue.Empty:
                    continue
                if is_report(message):
                    report = decode_report(message)
                    print(report.rpt_id, report.seq_num, [(e.index, e.value) for e in report.entries])
        finally:
            rcb.disable(client, free.rcb)
            print(f"released {free.rcb}")


if __name__ == "__main__":
    main()
