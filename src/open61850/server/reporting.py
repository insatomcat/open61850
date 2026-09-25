# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Reports of the MMS server (IEC 61850-7-2 clause 17, IEC 61850-8-1 clause 17).

A :class:`ReportEngine` attached to an :class:`~.server.MmsServer` makes its
report control blocks work:

- writes to a block's attributes go through it: reservation (Resv of a
  URCB, ResvTms and Owner of a BRCB; a block reserved or enabled by another
  client refuses with temporarily-unavailable), no configuration change
  while enabled, RptEna, GI (a general-interrogation report, then GI goes
  back to FALSE), PurgeBuf;
- value changes of the model (:meth:`~.model.IedModel.set`) become entries
  when a data set member covers the changed attribute and TrgOps asks for
  the reason (dchg, qchg of the attribute's SCL trigger options); BufTm
  gathers the entries of that many milliseconds into one report;
- IntgPd sends integrity reports; a BRCB keeps its entries in a buffer
  (EntryID, BufOvfl) that an enabling client receives from the entry after
  EntryID (all of it when EntryID is zero);
- when a client goes, its blocks are disabled; a BRCB stays reserved for
  ResvTms seconds.

Reports are informationReports on ``RPT``: RptID, OptFlds, then the
optional fields OptFlds asks for, the inclusion bit string, the data
references, the values and the reason codes (8-1 table 60).
"""

from __future__ import annotations

import collections
import dataclasses
import heapq
import ipaddress
import itertools
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Union

from ..data import (
    BitStringData,
    BoolData,
    IECData,
    IntData,
    OctetStringData,
    RawData,
    UIntData,
    VisibleStringData,
    encode_binary_time,
)
from ..mms.pdu import ObjectName
from ..mms.report import OptFlds, ReasonCode, TrgOps, bitstring_of
from . import protocol
from .model import (
    ACCESS_OBJECT_ACCESS_DENIED,
    ACCESS_OBJECT_NON_EXISTENT,
    ACCESS_TEMPORARILY_UNAVAILABLE,
    ACCESS_TYPE_INCONSISTENT,
    IedModel,
    Node,
    _fits,
)

__all__ = ["ReportEngine", "ReportControl", "BUFFER_ENTRIES"]

BUFFER_ENTRIES = 1000  # entries a BRCB keeps
_CONFIG = {"RptID", "DatSet", "ConfRev", "OptFlds", "BufTm", "TrgOps", "IntgPd"}


@dataclass
class _Entry:
    entry_id: int
    time: datetime
    reasons: dict[int, ReasonCode]  # member index -> reason
    values: dict[int, Union[IECData, int]] = field(default_factory=dict)  # an int: a DataAccessError code


class ReportControl:
    """One report control block instance (``LN$BR$name01``)."""

    def __init__(self, engine: ReportEngine, domain: str, node: Node) -> None:
        self.engine = engine
        self.domain = domain
        self.node = node
        self.buffered = node.fc == "BR"
        self.owner: object = None  # the ServerConnection that reserved or enabled it
        self.owner_address: Optional[str] = None
        self.reserved_until: Optional[float] = None  # a BRCB kept after its client left
        self.pending: Optional[_Entry] = None  # gathered for BufTm
        self.buffer: collections.deque[_Entry] = collections.deque(maxlen=BUFFER_ENTRIES)
        self.overflowed = False
        self.next_entry = 1
        self.integrity_due: Optional[float] = None
        self.ever_enabled = False  # a BRCB buffers from its first enabling on

    # --- attributes --------------------------------------------------------------

    def attr(self, name: str) -> Optional[IECData]:
        child = self.node.child(name) or (self.node.child("TimeofEntry") if name == "TimeOfEntry" else None)
        return None if child is None else child.data()

    def set_attr(self, name: str, value: IECData) -> None:
        child = self.node.child(name) or (self.node.child("TimeofEntry") if name == "TimeOfEntry" else None)
        if child is not None:
            child.assign(value)

    @property
    def enabled(self) -> bool:
        value = self.attr("RptEna")
        return isinstance(value, BoolData) and value.value

    def members(self) -> list[ObjectName]:
        dat_set = self.attr("DatSet")
        if not isinstance(dat_set, VisibleStringData) or "/" not in dat_set.value:
            return []
        domain, item = dat_set.value.split("/", 1)
        return self.engine.model.data_sets.get(ObjectName(item, domain), [])

    def trg_ops(self) -> TrgOps:
        value = self.attr("TrgOps")
        return TrgOps.from_bitstring(value) if isinstance(value, BitStringData) else TrgOps()

    def opt_flds(self) -> OptFlds:
        value = self.attr("OptFlds")
        return OptFlds.from_bitstring(value) if isinstance(value, BitStringData) else OptFlds()

    def _uint(self, name: str) -> int:
        value = self.attr(name)
        return value.value if isinstance(value, (UIntData, IntData)) else 0

    # --- reservation -------------------------------------------------------------

    def held_by_other(self, connection: object) -> bool:
        if self.owner is not None:
            return self.owner is not connection
        if self.reserved_until is not None and time.monotonic() < self.reserved_until:
            return getattr(connection, "address", None) != self.owner_address
        return False

    def take(self, connection: object) -> None:
        self.owner = connection
        self.reserved_until = None
        self.owner_address = getattr(connection, "address", None)
        if self.node.child("Owner") is not None:
            self.set_attr("Owner", OctetStringData(_address_bytes(self.owner_address)))
        if not self.buffered:
            self.set_attr("Resv", BoolData(True))

    def release(self, keep_seconds: float = 0.0) -> None:
        self.owner = None
        if keep_seconds > 0:
            self.reserved_until = time.monotonic() + keep_seconds
            return
        self.reserved_until = None
        self.owner_address = None
        if self.node.child("Owner") is not None:
            self.set_attr("Owner", OctetStringData(b""))
        if not self.buffered:
            self.set_attr("Resv", BoolData(False))


def _address_bytes(address: Optional[str]) -> bytes:
    try:
        return ipaddress.ip_address(address or "").packed
    except ValueError:
        return b""


class ReportEngine:
    """The report control blocks of a server's model, driven by writes, changes and time."""

    def __init__(self, server: object) -> None:
        from .server import MmsServer

        assert isinstance(server, MmsServer)
        self.server = server
        self.model: IedModel = server.model
        self.controls: dict[tuple[str, str], ReportControl] = {}  # (domain, item) -> block
        for domain, lns in self.model.logical_devices.items():
            for ln in lns.values():
                for fc in ("BR", "RP"):
                    fc_node = ln.child(fc)
                    for block in (fc_node.children.values() if fc_node is not None else ()):
                        self.controls[(domain, block.item)] = ReportControl(self, domain, block)
        self._lock = threading.RLock()
        self._timers: list[tuple[float, int, Callable[[], None]]] = []
        self._counter = itertools.count()
        self._wake = threading.Condition(self._lock)
        self._stopped = False
        self._thread = threading.Thread(target=self._run, name="mms-reports", daemon=True)
        server.write_hooks.append(self._on_write)
        server.close_hooks.append(self._on_close)
        self.model.add_listener(self._on_change)
        self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            self._wake.notify()
        self._thread.join(timeout=5)

    # --- scheduling ----------------------------------------------------------------

    def _at(self, due: float, action: Callable[[], None]) -> None:
        heapq.heappush(self._timers, (due, next(self._counter), action))
        self._wake.notify()

    def _run(self) -> None:
        with self._lock:
            while not self._stopped:
                now = time.monotonic()
                while self._timers and self._timers[0][0] <= now:
                    _due, _n, action = heapq.heappop(self._timers)
                    try:
                        action()
                    except Exception:
                        pass
                    now = time.monotonic()
                timeout = self._timers[0][0] - now if self._timers else None
                self._wake.wait(timeout)

    # --- writes ------------------------------------------------------------------------

    def _on_write(self, connection: object, name: ObjectName, value: IECData) -> Optional[int | bool]:
        parts = name.item.split("$")
        if len(parts) < 3 or parts[1] not in ("BR", "RP"):
            return None
        rcb = self.controls.get((name.domain or "", "$".join(parts[:3])))
        if rcb is None:
            return ACCESS_OBJECT_NON_EXISTENT
        if len(parts) != 4:
            return ACCESS_OBJECT_ACCESS_DENIED  # the whole block, or inside an attribute
        attribute = parts[3]
        node = rcb.node.child(attribute)
        if node is None or not _fits(node.mms_type, value):
            return ACCESS_TYPE_INCONSISTENT if node is not None else ACCESS_OBJECT_NON_EXISTENT
        with self._lock, self.model.lock:
            if rcb.held_by_other(connection):
                return ACCESS_TEMPORARILY_UNAVAILABLE
            if attribute in ("SqNum", "Owner", "TimeOfEntry", "TimeofEntry"):
                return ACCESS_OBJECT_ACCESS_DENIED
            if rcb.enabled and attribute in _CONFIG | {"PurgeBuf", "EntryID", "Resv", "ResvTms"}:
                return ACCESS_TEMPORARILY_UNAVAILABLE
            if attribute == "Resv":
                assert isinstance(value, BoolData)
                if value.value:
                    rcb.take(connection)
                else:
                    rcb.release()
                return True
            if attribute == "ResvTms":
                node.assign(value)
                if isinstance(value, IntData) and value.value != 0:
                    rcb.take(connection)
                elif rcb.owner is connection:
                    rcb.release()
                return True
            if attribute == "PurgeBuf":
                if isinstance(value, BoolData) and value.value:
                    rcb.buffer.clear()
                    rcb.overflowed = False
                return True
            if attribute == "GI":
                if isinstance(value, BoolData) and value.value and rcb.enabled:
                    self._general_interrogation(rcb)
                return True
            if attribute == "RptEna":
                assert isinstance(value, BoolData)
                if value.value and not rcb.enabled:
                    rcb.take(connection)
                    node.assign(value)
                    self._enabled(rcb)
                elif not value.value and rcb.enabled:
                    node.assign(value)
                    self._flush(rcb)
                    rcb.integrity_due = None
                return True
            node.assign(value)  # configuration, EntryID
            return True

    def _on_close(self, connection: object) -> None:
        with self._lock, self.model.lock:
            for rcb in self.controls.values():
                if rcb.owner is not connection:
                    continue
                rcb.set_attr("RptEna", BoolData(False))
                rcb.integrity_due = None
                resv_tms = rcb.attr("ResvTms")
                keep = resv_tms.value if isinstance(resv_tms, IntData) and resv_tms.value > 0 else 0
                rcb.release(keep_seconds=keep if rcb.buffered else 0)

    # --- enabling ------------------------------------------------------------------------

    def _enabled(self, rcb: ReportControl) -> None:
        rcb.ever_enabled = True
        if rcb.buffered:
            entry_id = rcb.attr("EntryID")
            start = int.from_bytes(entry_id.value, "big") if isinstance(entry_id, OctetStringData) else 0
            for entry in [e for e in rcb.buffer if e.entry_id > start]:
                self._send(rcb, entry)
        self._schedule_integrity(rcb)

    def _schedule_integrity(self, rcb: ReportControl) -> None:
        period = rcb._uint("IntgPd")
        if not period or not rcb.trg_ops().integrity:
            return
        due = time.monotonic() + period / 1000
        rcb.integrity_due = due

        def fire() -> None:
            if rcb.enabled and rcb.integrity_due == due:
                self._flush(rcb)
                self._report_all(rcb, ReasonCode(integrity=True))
                self._schedule_integrity(rcb)

        self._at(due, fire)

    def _general_interrogation(self, rcb: ReportControl) -> None:
        if rcb.trg_ops().general_interrogation:
            self._flush(rcb)
            self._report_all(rcb, ReasonCode(general_interrogation=True))

    def _report_all(self, rcb: ReportControl, reason: ReasonCode) -> None:
        members = rcb.members()
        entry = self._new_entry(rcb, {i: reason for i in range(len(members))})
        self._deliver(rcb, entry)

    # --- changes ------------------------------------------------------------------------

    def _on_change(self, changed: list[Node]) -> None:
        with self._lock, self.model.lock:
            for rcb in self.controls.values():
                if not rcb.enabled and not (rcb.buffered and rcb.ever_enabled):
                    continue
                trg = rcb.trg_ops()
                members = rcb.members()
                reasons: dict[int, ReasonCode] = {}
                for leaf in changed:
                    domain = self._domain_of(leaf)
                    for index, member in enumerate(members):
                        if member.domain != domain or not (leaf.item == member.item or leaf.item.startswith(member.item + "$")):
                            continue
                        reason = ReasonCode(
                            data_change="dchg" in leaf.triggers and trg.data_change,
                            quality_change="qchg" in leaf.triggers and trg.quality_change,
                            data_update="dupd" in leaf.triggers and trg.data_update,
                        )
                        if reason != ReasonCode():
                            reasons[index] = _merge(reasons.get(index), reason)
                if reasons:
                    self._add(rcb, reasons)

    def _domain_of(self, leaf: Node) -> str:
        root = leaf
        while root.parent is not None:
            root = root.parent
        for domain, lns in self.model.logical_devices.items():
            if lns.get(root.name) is root:
                return domain
        return ""

    def _add(self, rcb: ReportControl, reasons: dict[int, ReasonCode]) -> None:
        members = rcb.members()
        values = {i: self.model.read(members[i]) for i in reasons}  # the values of this change
        buf_tm = rcb._uint("BufTm")
        if buf_tm and rcb.enabled:
            if rcb.pending is None:
                rcb.pending = _Entry(0, datetime.now(timezone.utc), {})
                pending = rcb.pending
                self._at(time.monotonic() + buf_tm / 1000, lambda: self._flush(rcb) if rcb.pending is pending else None)
            if any(i in rcb.pending.reasons for i in reasons):
                self._flush(rcb)  # a member again: the gathered entry goes first
                self._add(rcb, reasons)
                return
            rcb.pending.reasons.update(reasons)
            rcb.pending.values.update(values)
            return
        self._deliver(rcb, self._new_entry(rcb, reasons, values))

    def _flush(self, rcb: ReportControl) -> None:
        pending, rcb.pending = rcb.pending, None
        if pending is not None and pending.reasons:
            self._deliver(rcb, self._new_entry(rcb, pending.reasons, pending.values))

    def _new_entry(self, rcb: ReportControl, reasons: dict[int, ReasonCode],
                   values: Optional[dict[int, Union[IECData, int]]] = None) -> _Entry:
        """An entry with ``values`` as they were at the change (read now when not given)."""
        members = rcb.members()
        entry = _Entry(rcb.next_entry, datetime.now(timezone.utc), dict(sorted(reasons.items())))
        rcb.next_entry += 1
        for index in entry.reasons:
            entry.values[index] = values[index] if values and index in values else self.model.read(members[index])
        return entry

    def _deliver(self, rcb: ReportControl, entry: _Entry) -> None:
        if rcb.buffered:
            if len(rcb.buffer) == rcb.buffer.maxlen:
                rcb.overflowed = True
            rcb.buffer.append(entry)
            rcb.set_attr("EntryID", OctetStringData(entry.entry_id.to_bytes(8, "big")))
            rcb.set_attr("TimeOfEntry", RawData(0x8C, encode_binary_time(entry.time)))
        if rcb.enabled:
            self._send(rcb, entry)

    # --- encoding ------------------------------------------------------------------------

    def _send(self, rcb: ReportControl, entry: _Entry) -> None:
        opt = rcb.opt_flds()
        if not rcb.buffered:
            # An unbuffered report has no BufOvfl and no EntryID: their bits go out cleared (as libiec61850 does).
            opt = dataclasses.replace(opt, buffer_overflow=False, entry_id=False)
        members = rcb.members()
        sq_num = rcb._uint("SqNum")
        values: list[Union[IECData, int]] = [rcb.attr("RptID") or VisibleStringData(""), opt.to_bitstring()]
        if opt.sequence_number:
            values.append(UIntData(sq_num))
        if opt.report_time_stamp:
            values.append(RawData(0x8C, encode_binary_time(entry.time)))
        if opt.data_set_name:
            values.append(rcb.attr("DatSet") or VisibleStringData(""))
        if rcb.buffered and opt.buffer_overflow:
            values.append(BoolData(rcb.overflowed))
        if rcb.buffered and opt.entry_id:
            values.append(OctetStringData(entry.entry_id.to_bytes(8, "big")))
        if opt.conf_revision:
            values.append(UIntData(rcb._uint("ConfRev")))
        included = [i in entry.reasons for i in range(len(members))]
        values.append(bitstring_of(included))
        indexes = [i for i in range(len(members)) if included[i]]
        if opt.data_reference:
            values += [VisibleStringData(f"{members[i].domain}/{members[i].item}") for i in indexes]
        values += [entry.values[i] for i in indexes]
        if opt.reason_for_inclusion:
            values += [entry.reasons[i].to_bitstring() for i in indexes]
        size = rcb.node.child("SqNum")
        modulo = 256 if size is not None and getattr(size.mms_type, "size", 8) == 8 else 65536
        rcb.set_attr("SqNum", UIntData((sq_num + 1) % modulo))
        rcb.overflowed = False
        connection = rcb.owner
        if connection is not None:
            self.server.broadcast(protocol.information_report(values, list_name="RPT"), to=connection)  # type: ignore[arg-type]


def _merge(a: Optional[ReasonCode], b: ReasonCode) -> ReasonCode:
    if a is None:
        return b
    return ReasonCode(**{k: getattr(a, k) or getattr(b, k) for k in vars(b)})
