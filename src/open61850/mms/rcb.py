# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Report control blocks (IEC 61850-7-2 BRCB / URCB over MMS, IEC 61850-8-1).

A BRCB is ``<LN>$BR$<name>``, a URCB ``<LN>$RP$<name>``. Servers often offer
several instances of the same block, one per client (``CB_X01``,
``CB_X02``...); :func:`find_free` picks one nobody uses.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from ..data import BoolData, IECData, IntData, OctetStringData, UIntData, VisibleStringData
from .client import MmsClient
from .errors import DataAccessError, MmsError
from .pdu import ObjectName
from .report import OptFlds, TrgOps

__all__ = [
    "RcbError",
    "is_rcb_name",
    "is_buffered",
    "instance_base",
    "group_instances",
    "RcbStatus",
    "read_status",
    "usable",
    "find_free",
    "RcbSettings",
    "enable",
    "disable",
]



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
    """Name of a block without its two-digit instance number (IEC 61850-8-1).

    ``..._DQPO03`` -> ``..._DQPO``, ``..._DQPO_DEP102`` -> ``..._DQPO_DEP1``.
    A block that is not indexed but whose name ends with two digits would be
    cut too; the SCL (``open61850.scl``) gives the exact names.
    """
    return re.sub(r"\d{2}$", "", item)


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
    def reserved_by_configuration(self) -> bool:
        """ResvTms = -1: the server assigned the block to a given client (SCL ClientLN)."""
        return self.resv_tms == -1

    def describe(self) -> str:
        """Short state: ``free``, or why the block is in use."""
        reasons = []
        if self.rpt_ena:
            reasons.append("enabled")
        if self.resv:
            reasons.append("reserved")
        if self.reserved_by_configuration:
            reasons.append("assigned by configuration")
        elif self.resv_tms not in (None, 0):
            reasons.append(f"reserved {self.resv_tms}s")
        if not reasons:
            return "free"
        owner = _format_owner(self.owner)
        return ", ".join(reasons) + (f", owner {owner}" if owner else "")

    @property
    def free(self) -> bool:
        """Neither enabled nor reserved."""
        if self.rpt_ena:
            return False
        if self.resv:
            return False
        if self.resv_tms not in (None, 0):
            return False
        return True

    def available_to(self, address: Optional[str]) -> bool:
        """Free, or reserved but not enabled by ``address`` (an earlier association of ours).

        Some servers (the VMC7) keep ResvTms and Owner after the association
        that reserved the block is gone, so a restarted client finds its own
        old reservations. A block reserved by configuration (ResvTms = -1) is
        never taken.
        """
        if self.free:
            return True
        if self.rpt_ena or self.reserved_by_configuration or not address:
            return False
        return _format_owner(self.owner) == address


_STATUS_ATTRIBUTES = ("RptEna", "RptID", "DatSet", "Owner")


def _format_owner(owner: Optional[bytes]) -> Optional[str]:
    """Owner holds the client address; all zeros means none."""
    if not owner or not any(owner):
        return None
    if len(owner) == 4:
        return ".".join(str(b) for b in owner)
    if len(owner) == 16:
        return str(ipaddress.IPv6Address(owner))
    return owner.hex()


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


def usable(client: MmsClient, candidates: list[ObjectName], *, reclaim_own: bool = True) -> list[RcbStatus]:
    """The blocks among ``candidates`` worth trying, best first.

    Free blocks come first; with ``reclaim_own``, blocks this client's
    address reserved earlier but did not enable follow. The server may still
    refuse one of those (the reservation belongs to another association):
    try the next.
    """
    address = client.local_address if reclaim_own else None
    statuses = [read_status(client, rcb) for rcb in candidates]
    return [s for s in statuses if s.free] + [s for s in statuses if not s.free and s.available_to(address)]


def find_free(client: MmsClient, candidates: list[ObjectName], *, reclaim_own: bool = True) -> Optional[RcbStatus]:
    """First usable block among ``candidates`` (see :func:`usable`)."""
    found = usable(client, candidates, reclaim_own=reclaim_own)
    return found[0] if found else None


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
    # BRCB reservation (edition 2), in seconds it survives a lost association.
    # Written first: servers refuse configuration writes from a client that has
    # not reserved the block (the VMC7 answers temporarily-unavailable).
    resv_tms: Optional[int] = 5
    purge_buf: Optional[bool] = None  # BRCB only
    entry_id: Optional[bytes] = None  # BRCB only
    general_interrogation: bool = True


_OBJECT_NON_EXISTENT = 10
_EDITION_2_ONLY = ("ResvTms",)  # absent from edition 1 BRCBs


def enable(client: MmsClient, rcb: ObjectName, settings: Optional[RcbSettings] = None) -> None:
    """Reserve, configure and enable a block, then trigger a general interrogation.

    Each write is checked; the first failure raises :class:`RcbError`. A
    BRCB without ResvTms (edition 1, e.g. the SSC600) is enabled without
    reservation.
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
            if attribute in _EDITION_2_ONLY and exc.code == _OBJECT_NON_EXISTENT:
                continue
            raise RcbError(rcb, attribute, exc) from exc


def disable(client: MmsClient, rcb: ObjectName) -> None:
    """Disable a block and release its reservation."""
    client.write(_attr(rcb, "RptEna"), BoolData(False))
    if is_buffered(rcb):
        try:
            client.write(_attr(rcb, "ResvTms"), IntData(0))
        except DataAccessError as exc:
            if exc.code != _OBJECT_NON_EXISTENT:
                raise
    else:
        client.write(_attr(rcb, "Resv"), BoolData(False))
