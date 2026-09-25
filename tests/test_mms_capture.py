# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.mms on real traffic: IEDscout subscribed to a BRCB and operated a breaker.

In that capture IEDscout enabled the block with only two writes (ResvTms = 42
then RptEna = TRUE), keeping the IED's TrgOps and OptFlds, and operated the
breaker with a single Oper write per command (direct control with enhanced
security): write response after 2 ms, CommandTermination 60 to 90 ms later.
"""

from __future__ import annotations

import json

from conftest import DATA_DIR

from open61850 import ber
from open61850.data import (
    BitStringData,
    BoolData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    decode_data_sequence,
)
from open61850.mms import InformationReport, ObjectName, OptFlds, ReasonCode, decode_report, is_report, pdu

CAPTURE = json.loads((DATA_DIR / "iedscout_reports_control.json").read_text())
OPER = ObjectName("CBCSWI1$CO$Pos$Oper", "IED01_BayLD")


def _incoming(key: str) -> pdu.IncomingPdu:
    return pdu.decode_pdu(pdu.unwrap(bytes.fromhex(CAPTURE[key])))


def test_full_integrity_report() -> None:
    message = _incoming("report_full")
    assert isinstance(message, InformationReport) and is_report(message)
    report = decode_report(message)
    assert report.rpt_id == "LDCTRL1_DQPO_DEP1"
    assert report.data_set == "IED01_LD0/LLN0$DS_LDCTRL1_DQPO"
    assert report.opt_flds == OptFlds(  # the IED's own configuration: 7a00
        sequence_number=True, report_time_stamp=True, reason_for_inclusion=True, data_set_name=True, buffer_overflow=True,
    )
    assert report.entry_id is None and report.conf_rev is None
    assert len(report.inclusion) == 19 and all(report.inclusion)
    assert [e.index for e in report.entries] == list(range(19))
    assert {e.reason for e in report.entries} == {ReasonCode(integrity=True)}


def test_partial_data_change_report() -> None:
    report = decode_report(_incoming("report_data_change"))  # type: ignore[arg-type]
    assert [e.index for e in report.entries] == [7, 8]
    assert all(e.reason == ReasonCode(data_change=True) for e in report.entries)
    first = report.entries[0].value
    assert isinstance(first, StructureData) and first.members[0] == BoolData(False)
    assert first.members[1] == BitStringData(b"\x00\x00", 3)


def test_iedscout_oper_write() -> None:
    request = ber.decode_tlv(pdu.unwrap(bytes.fromhex(CAPTURE["oper_write_req"])))
    service = list(ber.iter_tlvs(request.value))[1]
    assert ber.tag_number(service.tag) == pdu.SERVICE_WRITE
    spec, data = list(ber.iter_tlvs(service.value))[:2]
    assert pdu._decode_variable_list(spec.value) == [OPER]
    (oper,) = decode_data_sequence(data.value)
    assert isinstance(oper, StructureData)
    ctl_val, origin, ctl_num, t, test, check = oper.members
    assert ctl_val == BoolData(True)  # close
    assert origin == StructureData([IntData(2), OctetStringData(bytes.fromhex("13d5c007"))])  # station-control
    assert ctl_num == UIntData(0)
    assert isinstance(t, TimestampData) and t.quality == 0x3F
    assert test == BoolData(False)
    assert check == BitStringData(b"\xc0", 6)  # synchrocheck + interlock-check


def test_command_termination() -> None:
    message = _incoming("command_termination")
    assert isinstance(message, InformationReport) and not is_report(message)
    assert message.list_name is None and message.variables == [OPER]
    (echo,) = message.results
    assert isinstance(echo, StructureData) and echo.members[0] == BoolData(True)
