# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Report control blocks (IEC 61850-7-2 BRCB / URCB over MMS, IEC 61850-8-1).

A BRCB is ``<LN>$BR$<name>``, a URCB ``<LN>$RP$<name>``. Servers often offer
several instances of the same block, one per client (``CB_X01``,
``CB_X02``...); :func:`find_free` picks one nobody uses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..data import BoolData, IECData, IntData, OctetStringData, UIntData, VisibleStringData
from .client import MmsClient
from .errors import DataAccessError, MmsError
from .pdu import ObjectName
from .report import OptFlds, TrgOps


class RcbError(MmsError):
    """Writing an attribute of a report control block failed."""

    def __init__(self, rcb: ObjectName, attribute: str, cause: DataAccessError) -> None:
        self.rcb = rcb
        self.attribute = attribute
        self.cause = cause
        super().__init__(f"{rcb}${attribute}: {cause}")


def is_rcb_name(item: str) -> bool:
    """True for ``<LN>$BR$<name>`` or ``<LN>$RP$<name>`` (its attributes excluded)."""
    parts = item.split("$")
    return len(parts) == 3 and parts[1] in ("BR", "RP")


def is_buffered(rcb: ObjectName) -> bool:
    return rcb.item.split("$")[1] == "BR"


def instance_base(item: str) -> str:
    """Name of a block without its trailing instance number (``..._DQPO03`` -> ``..._DQPO``)."""
    return re.sub(r"\d+$", "", item)


def group_instances(rcbs: list[ObjectName]) -> dict[tuple[Optional[str], str], list[ObjectName]]:
    """Group blocks that only differ by their trailing instance number."""
    groups: dict[tuple[Optional[str], str], list[ObjectName]] = {}
    for rcb in rcbs:
        groups.setdefault((rcb.domain, instance_base(rcb.item)), []).append(rcb)
    for members in groups.values():
        members.sort(key=lambda r: r.item)
    return groups


def _attr(rcb: ObjectName, attribute: str) -> ObjectName:
    return ObjectName(f"{rcb.item}${attribute}", rcb.domain)


@dataclass
class RcbStatus:
    rcb: ObjectName
    rpt_ena: Optional[bool] = None
    resv: Optional[bool] = None  # URCB
    resv_tms: Optional[int] = None  # BRCB (edition 2)
    owner: Optional[bytes] = None
    rpt_id: Optional[str] = None
    dat_set: Optional[str] = None

    @property
    def free(self) -> bool:
        """Neither enabled nor reserved by another client."""
        if self.rpt_ena:
            return False
        if self.resv:
            return False
        if self.resv_tms not in (None, 0):
            return False
        return True


_STATUS_ATTRIBUTES = ("RptEna", "RptID", "DatSet", "Owner")


def read_status(client: MmsClient, rcb: ObjectName) -> RcbStatus:
    """Read the enable/reservation state of a block; optional attributes may be missing."""
    attrs = list(_STATUS_ATTRIBUTES) + (["ResvTms"] if is_buffered(rcb) else ["Resv"])
    values = dict(zip(attrs, client.read_many([_attr(rcb, a) for a in attrs])))

    def get(name: str, kind: type) -> Optional[IECData]:
        value = values.get(name)
        return value if isinstance(value, kind) else None

    status = RcbStatus(rcb)
    if (v := get("RptEna", BoolData)) is not None:
        status.rpt_ena = v.value  # type: ignore[union-attr]
    if (v := get("Resv", BoolData)) is not None:
        status.resv = v.value  # type: ignore[union-attr]
    if (v := get("ResvTms", (IntData, UIntData))) is not None:  # type: ignore[arg-type]
        status.resv_tms = v.value  # type: ignore[union-attr]
    if (v := get("Owner", OctetStringData)) is not None:
        status.owner = v.value  # type: ignore[union-attr]
    if (v := get("RptID", VisibleStringData)) is not None:
        status.rpt_id = v.value  # type: ignore[union-attr]
    if (v := get("DatSet", VisibleStringData)) is not None:
        status.dat_set = v.value  # type: ignore[union-attr]
    return status


def find_free(client: MmsClient, candidates: list[ObjectName]) -> Optional[RcbStatus]:
    """First free block among ``candidates`` (e.g. the instances of one group)."""
    for rcb in candidates:
        status = read_status(client, rcb)
        if status.free:
            return status
    return None


@dataclass
class RcbSettings:
    """What to write before enabling a block. ``None`` leaves the attribute untouched."""

    trg_ops: Optional[TrgOps] = field(
        default_factory=lambda: TrgOps(data_change=True, quality_change=True, integrity=True, general_interrogation=True)
    )
    opt_flds: Optional[OptFlds] = field(
        default_factory=lambda: OptFlds(
            sequence_number=True, report_time_stamp=True, reason_for_inclusion=True, data_set_name=True,
            buffer_overflow=True, entry_id=True, conf_revision=True,
        )
    )
    intg_pd_ms: Optional[int] = 2000
    buf_tm_ms: Optional[int] = None
    resv_tms: Optional[int] = None  # BRCB reservation time in seconds (edition 2)
    purge_buf: Optional[bool] = None  # BRCB only
    entry_id: Optional[bytes] = None  # BRCB only
    general_interrogation: bool = True


def enable(client: MmsClient, rcb: ObjectName, settings: Optional[RcbSettings] = None) -> None:
    """Reserve, configure and enable a block, then trigger a general interrogation.

    Each write is checked; the first failure raises :class:`RcbError`.
    """
    s = settings or RcbSettings()
    buffered = is_buffered(rcb)
    writes: list[tuple[str, IECData]] = []
    if buffered and s.resv_tms is not None:
        writes.append(("ResvTms", IntData(s.resv_tms)))
    if not buffered:
        writes.append(("Resv", BoolData(True)))
    if s.intg_pd_ms is not None:
        writes.append(("IntgPd", UIntData(s.intg_pd_ms)))
    if s.buf_tm_ms is not None:
        writes.append(("BufTm", UIntData(s.buf_tm_ms)))
    if s.trg_ops is not None:
        writes.append(("TrgOps", s.trg_ops.to_bitstring()))
    if s.opt_flds is not None:
        writes.append(("OptFlds", s.opt_flds.to_bitstring()))
    if buffered and s.purge_buf is not None:
        writes.append(("PurgeBuf", BoolData(s.purge_buf)))
    if buffered and s.entry_id is not None:
        writes.append(("EntryID", OctetStringData(s.entry_id)))
    writes.append(("RptEna", BoolData(True)))
    if s.general_interrogation:
        writes.append(("GI", BoolData(True)))
    for attribute, value in writes:
        try:
            client.write(_attr(rcb, attribute), value)
        except DataAccessError as exc:
            raise RcbError(rcb, attribute, exc) from exc


def disable(client: MmsClient, rcb: ObjectName) -> None:
    """Disable a block and release its reservation."""
    client.write(_attr(rcb, "RptEna"), BoolData(False))
    if not is_buffered(rcb):
        client.write(_attr(rcb, "Resv"), BoolData(False))
