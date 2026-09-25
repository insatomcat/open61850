# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Command-line MMS client (``open61850-mms`` or ``python -m open61850.mms``).

    open61850-mms HOST[:PORT] association
    open61850-mms HOST[:PORT] domains
    open61850-mms HOST[:PORT] rcbs [--status]
    open61850-mms HOST[:PORT] read DOMAIN/ITEM [DOMAIN/ITEM ...]
    open61850-mms HOST[:PORT] dataset DOMAIN/LLN0$DSNAME
    open61850-mms HOST[:PORT] subscribe DOMAIN/LLN0$BR$NAME [--integrity-ms 2000]
    open61850-mms HOST[:PORT] operate DOMAIN/LN$CO$DO open|close|true|false|NUMBER

``subscribe`` takes a block or the name of a group without its instance
number (``IED01_LD0/LLN0$BR$CB_LDPHAS1_DQPO``): it picks a free instance,
enables it, prints the decoded reports and disables it on Ctrl-C.

``association`` prints what the server accepted: largest PDU, requests
in flight, nesting level and the services it supports.

``operate`` runs one control (station-control origin) with the object's own
control model and prints the outcome, or the AddCause of a refusal.
"""

from __future__ import annotations

import argparse
import queue
import sys
from typing import Optional

from open61850.display import format_value
from open61850.mms import (
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    InformationReport,
    MmsClient,
    MmsError,
    ObjectName,
    decode_report,
    is_report,
    MmsType,
    control,
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


# ServiceSupportOptions bits worth showing (ISO 9506-2).
SERVICES = {
    0: "status", 1: "getNameList", 2: "identify", 4: "read", 5: "write",
    6: "getVariableAccessAttributes", 12: "getNamedVariableListAttributes",
    72: "fileOpen", 73: "fileRead", 74: "fileClose", 77: "fileDirectory",
    79: "informationReport", 83: "conclude", 84: "cancel",
}


def cmd_association(client: MmsClient, _args: argparse.Namespace) -> None:
    a = client.association
    assert a is not None
    print(f"max PDU size         {a.max_pdu_size}")
    print(f"requests in flight   {a.max_outstanding_calling} (server side {a.max_outstanding_called})")
    print(f"data nesting level   {a.nesting_level}")
    print(f"MMS version          {a.version}")
    print("services             " + ", ".join(name for bit, name in SERVICES.items() if a.supports(bit)))


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
    names = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, target.domain)
    blocks = [ObjectName(n, target.domain) for n in names if rcb.is_rcb_name(n)]
    # An instance by its full name, or a block by its name without instance number.
    candidates = [b for b in blocks if b.item == target.item] or [
        b for b in blocks if rcb.instance_base(b.item) == target.item
    ]
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


def parse_ctl_val(text: str) -> control.CtlValue:
    lowered = text.lower()
    if lowered in ("close", "on", "true"):
        return True
    if lowered in ("open", "off", "false"):
        return False
    return float(text) if "." in text else int(text)


def cmd_operate(client: MmsClient, args: argparse.Namespace) -> None:
    obj = control.control_object_name(args.name)
    ctl_model = control.read_ctl_model(client, obj)
    print(f"{obj}: {control.CTL_MODELS.get(ctl_model, ctl_model)}", flush=True)
    result = control.operate(
        client, obj, args.value, origin=control.Origin(control.OR_CAT_STATION_CONTROL, b"po"),
        ctl_num=args.ctl_num, test=args.test, ctl_model=ctl_model,
    )
    print(f"done: {result}")


def _type_or_none(client: MmsClient, name: ObjectName) -> Optional[MmsType]:
    try:
        return client.get_type(name)
    except MmsError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("server", help="HOST or HOST:PORT (default port 102)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("association")
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
    p = sub.add_parser("operate")
    p.add_argument("name", type=parse_name)
    p.add_argument("value", type=parse_ctl_val)
    p.add_argument("--ctl-num", type=int, default=0)
    p.add_argument("--test", action="store_true", help="set the Test flag")
    args = parser.parse_args()

    host, _, port = args.server.partition(":")
    reports: queue.Queue[InformationReport] = queue.Queue()
    try:
        with MmsClient.connect(host, int(port or 102), on_information_report=reports.put) as client:
            if args.command == "subscribe":
                cmd_subscribe(client, args, reports)
            else:
                {
                    "association": cmd_association, "domains": cmd_domains, "rcbs": cmd_rcbs, "read": cmd_read, "dataset": cmd_dataset,
                    "operate": cmd_operate,
                }[args.command](
                    client, args
                )
    except MmsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
