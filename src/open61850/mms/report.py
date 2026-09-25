# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""IEC 61850 reports carried by MMS informationReports (IEC 61850-8-1).

A report is an informationReport on the vmd-specific list ``RPT`` whose
access results are, in order, each field present when its OptFlds bit is set::

    RptID, OptFlds, [SeqNum], [TimeOfEntry], [DatSet], [BufOvfl], [EntryID],
    [ConfRev], [SubSeqNum, MoreSegmentsFollow], InclusionBitstring,
    [data-reference x n], value x n, [ReasonCode x n]

where n is the number of bits set in the inclusion bitstring.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Optional

from ..data import BitStringData, BoolData, IECData, IntData, OctetStringData, TimestampData, UIntData, VisibleStringData
from .errors import DataAccessError, MmsProtocolError
from .pdu import InformationReport

__all__ = [
    "bits_of",
    "bitstring_of",
    "OptFlds",
    "TrgOps",
    "ReasonCode",
    "ReportEntry",
    "Report",
    "ReportDecodeError",
    "is_report",
    "decode_report",
]



def bits_of(value: BitStringData) -> list[bool]:
    """The bits of a bit string, first bit first."""
    out = []
    for byte in value.value:
        out.extend(bool(byte & (0x80 >> i)) for i in range(8))
    return out[: len(out) - value.unused_bits] if value.unused_bits else out


def bitstring_of(flags: list[bool]) -> BitStringData:
    """Pack booleans into a bit string, first bit first."""
    raw = bytearray((len(flags) + 7) // 8)
    for i, flag in enumerate(flags):
        if flag:
            raw[i // 8] |= 0x80 >> (i % 8)
    return BitStringData(bytes(raw), (8 - len(flags) % 8) % 8)


class _Flags:
    """Named bits of a fixed-size bit string; subclasses list the fields in bit order."""

    SIZE = 0

    @classmethod
    def from_bitstring(cls, value: BitStringData):  # type: ignore[no-untyped-def]
        bits = bits_of(value) + [False] * cls.SIZE
        names = [f.name for f in fields(cls)]  # type: ignore[arg-type]
        return cls(**{name: bits[i + 1] for i, name in enumerate(names)})  # bit 0 is reserved

    def to_bitstring(self) -> BitStringData:
        values = [getattr(self, f.name) for f in fields(self)]  # type: ignore[arg-type]
        return bitstring_of([False, *values][: self.SIZE])


@dataclass(frozen=True)
class OptFlds(_Flags):
    """Optional fields of a report (bit 0 is reserved)."""

    SIZE = 10

    sequence_number: bool = False
    report_time_stamp: bool = False
    reason_for_inclusion: bool = False
    data_set_name: bool = False
    data_reference: bool = False
    buffer_overflow: bool = False
    entry_id: bool = False
    conf_revision: bool = False
    segmentation: bool = False


@dataclass(frozen=True)
class TrgOps(_Flags):
    """Trigger options of a report control block (bit 0 is reserved)."""

    SIZE = 6

    data_change: bool = False
    quality_change: bool = False
    data_update: bool = False
    integrity: bool = False
    general_interrogation: bool = False


@dataclass(frozen=True)
class ReasonCode(_Flags):
    """Why a member was included in a report (bit 0 is reserved)."""

    SIZE = 7

    data_change: bool = False
    quality_change: bool = False
    data_update: bool = False
    integrity: bool = False
    general_interrogation: bool = False
    application_trigger: bool = False


@dataclass
class ReportEntry:
    index: int  # position of the member in the data set
    value: IECData
    reference: Optional[str] = None
    reason: Optional[ReasonCode] = None


@dataclass
class Report:
    rpt_id: str
    opt_flds: OptFlds
    seq_num: Optional[int] = None
    time_of_entry: Optional[datetime] = None
    data_set: Optional[str] = None
    buf_ovfl: Optional[bool] = None
    entry_id: Optional[bytes] = None
    conf_rev: Optional[int] = None
    sub_seq_num: Optional[int] = None
    more_segments_follow: Optional[bool] = None
    inclusion: list[bool] = field(default_factory=list)
    entries: list[ReportEntry] = field(default_factory=list)


class ReportDecodeError(MmsProtocolError):
    """An informationReport on RPT does not follow the IEC 61850 layout."""


def is_report(message: InformationReport) -> bool:
    return message.list_name is not None and message.list_name.domain is None and message.list_name.item == "RPT"


def decode_report(message: InformationReport) -> Report:
    """Decode an IEC 61850 report from an informationReport on ``RPT``."""
    if not is_report(message):
        raise ReportDecodeError("not an informationReport on RPT")
    results = list(message.results)
    pos = 0

    def take(kind: type, what: str) -> IECData:
        nonlocal pos
        if pos >= len(results):
            raise ReportDecodeError(f"report truncated before {what}")
        value = results[pos]
        pos += 1
        if isinstance(value, DataAccessError):
            raise ReportDecodeError(f"{what} is an access error: {value}")
        if not isinstance(value, kind):
            raise ReportDecodeError(f"{what} should be {kind.__name__}, got {value!r}")
        return value

    def take_uint(what: str) -> int:
        nonlocal pos
        value = results[pos] if pos < len(results) else None
        if isinstance(value, IntData):  # some servers send INT32U fields as integer
            pos += 1
            return value.value
        return take(UIntData, what).value  # type: ignore[union-attr]

    report = Report(
        rpt_id=take(VisibleStringData, "RptID").value,  # type: ignore[union-attr]
        opt_flds=OptFlds.from_bitstring(take(BitStringData, "OptFlds")),  # type: ignore[arg-type]
    )
    opt = report.opt_flds
    if opt.sequence_number:
        report.seq_num = take_uint("SeqNum")
    if opt.report_time_stamp:
        report.time_of_entry = take(TimestampData, "TimeOfEntry").value  # type: ignore[union-attr]
    if opt.data_set_name:
        report.data_set = take(VisibleStringData, "DatSet").value  # type: ignore[union-attr]
    if opt.buffer_overflow:
        report.buf_ovfl = take(BoolData, "BufOvfl").value  # type: ignore[union-attr]
    if opt.entry_id:
        report.entry_id = take(OctetStringData, "EntryID").value  # type: ignore[union-attr]
    if opt.conf_revision:
        report.conf_rev = take_uint("ConfRev")
    if opt.segmentation:
        report.sub_seq_num = take_uint("SubSeqNum")
        report.more_segments_follow = take(BoolData, "MoreSegmentsFollow").value  # type: ignore[union-attr]
    report.inclusion = bits_of(take(BitStringData, "InclusionBitstring"))  # type: ignore[arg-type]
    indexes = [i for i, included in enumerate(report.inclusion) if included]

    references: list[Optional[str]] = [None] * len(indexes)
    if opt.data_reference:
        references = [take(VisibleStringData, "data-reference").value for _ in indexes]  # type: ignore[union-attr]
    values = []
    for _ in indexes:
        if pos >= len(results):
            raise ReportDecodeError("report truncated in the values")
        values.append(results[pos])
        pos += 1
    reasons: list[Optional[ReasonCode]] = [None] * len(indexes)
    if opt.reason_for_inclusion:
        reasons = [ReasonCode.from_bitstring(take(BitStringData, "ReasonCode")) for _ in indexes]  # type: ignore[arg-type]
    if pos != len(results):
        raise ReportDecodeError(f"{len(results) - pos} unexpected trailing results")

    report.entries = [
        ReportEntry(index, value, reference, reason)  # type: ignore[arg-type]
        for index, value, reference, reason in zip(indexes, values, references, reasons)
    ]
    return report
