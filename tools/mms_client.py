#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Command-line MMS client built on iec61850.mms.

    python3 tools/mms_client.py HOST[:PORT] domains
    python3 tools/mms_client.py HOST[:PORT] rcbs [--status]
    python3 tools/mms_client.py HOST[:PORT] read DOMAIN/ITEM [DOMAIN/ITEM ...]
    python3 tools/mms_client.py HOST[:PORT] dataset DOMAIN/LLN0$DSNAME
    python3 tools/mms_client.py HOST[:PORT] subscribe DOMAIN/LLN0$BR$NAME [--integrity-ms 2000]

``subscribe`` takes a block or the name of a group without its instance
number (``IED01_LD0/LLN0$BR$CB_LDPHAS1_DQPO``): it picks a free instance,
enables it, prints the decoded reports and disables it on Ctrl-C.
"""

from __future__ import annotations

import argparse
import queue
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iec61850.display import format_value  # noqa: E402
from iec61850.mms import (  # noqa: E402
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    InformationReport,
    MmsClient,
    MmsError,
    ObjectName,
    decode_report,
    is_report,
    MmsType,
    rcb,
)


def parse_name(text: str) -> ObjectName:
    if "/" not in text:
        raise argparse.ArgumentTypeError(f"expected DOMAIN/ITEM, got {text!r}")
    domain, item = text.split("/", 1)
    return ObjectName(item, domain)


def all_rcbs(client: MmsClient) -> list[ObjectName]:
    found = []
    for domain in client.get_name_list(OBJECT_CLASS_DOMAIN):
        names = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, domain)
        found += [ObjectName(n, domain) for n in names if rcb.is_rcb_name(n)]
    return found


def cmd_domains(client: MmsClient, _args: argparse.Namespace) -> None:
    for domain in client.get_name_list(OBJECT_CLASS_DOMAIN):
        print(domain)


def cmd_rcbs(client: MmsClient, args: argparse.Namespace) -> None:
    for (domain, base), members in rcb.group_instances(all_rcbs(client)).items():
        if not args.status:
            print(f"{domain}/{base}  x{len(members)}")
            continue
        print(f"{domain}/{base}")
        for member in members:
            status = rcb.read_status(client, member)
            print(f"    {member.item[len(base):]}: {status.describe()}")


def cmd_read(client: MmsClient, args: argparse.Namespace) -> None:
    for name, result in zip(args.names, client.read_many(args.names)):
        print(f"{name} = {result!r}")


def cmd_dataset(client: MmsClient, args: argparse.Namespace) -> None:
    for i, member in enumerate(client.get_data_set_members(args.name)):
        print(f"[{i}] {member}")


def cmd_subscribe(client: MmsClient, args: argparse.Namespace, reports: queue.Queue[InformationReport]) -> None:
    target: ObjectName = args.name
    if rcb.is_rcb_name(target.item) and target.item[-1].isdigit():
        candidates = [target]
    else:
        base = rcb.instance_base(target.item)
        candidates = [r for r in all_rcbs(client) if r.domain == target.domain and rcb.instance_base(r.item) == base]
    if not candidates:
        sys.exit(f"no report control block matches {target}")
    status = rcb.find_free(client, candidates)
    if status is None:
        sys.exit(f"all instances are in use: {', '.join(c.item for c in candidates)}")
    members: list[ObjectName] = []
    types: list[Optional[MmsType]] = []
    if status.dat_set and "/" in status.dat_set:
        ds_domain, ds_item = status.dat_set.split("/", 1)
        members = client.get_data_set_members(ObjectName(ds_item, ds_domain))
        types = [_type_or_none(client, m) for m in members]
    settings = rcb.RcbSettings(intg_pd_ms=args.integrity_ms, purge_buf=True if rcb.is_buffered(status.rcb) else None)
    print(f"enabling {status.rcb} (RptID {status.rpt_id}, data set {status.dat_set}, {len(members)} members)")
    rcb.enable(client, status.rcb, settings)
    try:
        while client.is_connected:
            try:
                message = reports.get(timeout=1)
            except queue.Empty:
                continue
            if not is_report(message):
                print(f"informationReport {message.variables}: {message.results}")
                continue
            report = decode_report(message)
            print(f"\n{report.rpt_id} seq={report.seq_num} time={report.time_of_entry} "
                  f"ds={report.data_set} bufOvfl={report.buf_ovfl}")
            for entry in report.entries:
                name = str(members[entry.index]) if entry.index < len(members) else f"[{entry.index}]"
                mms_type = types[entry.index] if entry.index < len(types) else None
                reason = [k for k, v in vars(entry.reason).items() if v] if entry.reason else []
                print(f"  {name}  ({','.join(reason)})")
                print(f"      {format_value(entry.value, mms_type)}")
    except KeyboardInterrupt:
        pass
    finally:
        if client.is_connected:
            rcb.disable(client, status.rcb)
            print(f"\ndisabled {status.rcb}")


def _type_or_none(client: MmsClient, name: ObjectName) -> Optional[MmsType]:
    try:
        return client.get_type(name)
    except MmsError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("server", help="HOST or HOST:PORT (default port 102)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("domains")
    p = sub.add_parser("rcbs")
    p.add_argument("--status", action="store_true", help="read RptEna/Resv of every instance")
    p = sub.add_parser("read")
    p.add_argument("names", nargs="+", type=parse_name)
    p = sub.add_parser("dataset")
    p.add_argument("name", type=parse_name)
    p = sub.add_parser("subscribe")
    p.add_argument("name", type=parse_name)
    p.add_argument("--integrity-ms", type=int, default=2000)
    args = parser.parse_args()

    host, _, port = args.server.partition(":")
    reports: queue.Queue[InformationReport] = queue.Queue()
    try:
        with MmsClient.connect(host, int(port or 102), on_information_report=reports.put) as client:
            if args.command == "subscribe":
                cmd_subscribe(client, args, reports)
            else:
                {"domains": cmd_domains, "rcbs": cmd_rcbs, "read": cmd_read, "dataset": cmd_dataset}[args.command](
                    client, args
                )
    except MmsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
