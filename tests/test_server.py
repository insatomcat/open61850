# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The MMS server (open61850.server), with the open61850 client on loopback.

tests/test_interop_libiec61850.py runs libiec61850's clients against it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from conftest import DATA_DIR

from open61850 import ber, scl
from open61850.data import BoolData, IntData, OctetStringData, StructureData, TimestampData, UIntData, VisibleStringData
from open61850.mms import (
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    OBJECT_CLASS_NAMED_VARIABLE_LIST,
    DataAccessError,
    MmsClient,
    MmsReject,
    ObjectName,
    ServiceError,
    discover,
    pdu,
)
from open61850.mms.model import compare
from open61850.mms.types import PrimitiveType, StructureType
from open61850.server import IedModel, MmsServer

SCD = DATA_DIR / "goose_sv.scd.xml"
PROT = "IED01_Protection"


@pytest.fixture
def model() -> IedModel:
    return IedModel.from_scl(SCD)


@pytest.fixture
def server(model: IedModel) -> Iterator[MmsServer]:
    with MmsServer(model, "127.0.0.1", 0) as srv:
        srv.start()
        yield srv


def test_model_from_scl(model: IedModel) -> None:
    assert list(model.logical_devices) == [PROT, "IED01MU"]
    lln0 = model.node(f"{PROT}/LLN0")
    assert [fc for fc in lln0.children] == ["ST", "CO", "CF", "BR", "GO"]  # libiec61850's order
    assert model.get(f"{PROT}/LLN0.brcbTrip01.RptID[BR]") == VisibleStringData(f"{PROT}/LLN0$BR$brcbTrip01")
    assert model.get(f"{PROT}/LLN0$BR$brcbTrip02$DatSet") == VisibleStringData(f"{PROT}/LLN0$DS_TRIP")
    assert model.get(f"{PROT}/LLN0$GO$gcbTrip$GoID") == VisibleStringData("TRIP_GOOSE")
    assert model.data_sets[ObjectName("LLN0$DS_TRIP", PROT)] == [
        ObjectName("PTRC1$ST$Tr$general", PROT), ObjectName("IMMXU1$MX$A$phsA", "IED01MU")]
    assert model.node(f"{PROT}/PTRC1$ST$Tr$general").triggers == frozenset({"dchg"})
    with pytest.raises(KeyError):
        model.get(f"{PROT}/LLN0$ST$Nope")


def test_set_checks_types_and_notifies(model: IedModel) -> None:
    seen = []
    model.add_listener(lambda nodes: seen.append([n.item for n in nodes]))
    model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)
    model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)  # no change, no notification
    model.set("IED01MU/IMMXU1.A.phsA.cVal.mag.f[MX]", 12.5)
    assert seen == [["PTRC1$ST$Tr$general"], ["IMMXU1$MX$A$phsA$cVal$mag$f"]]
    with pytest.raises(TypeError):
        model.set(f"{PROT}/PTRC1.Tr.general[ST]", VisibleStringData("x"))
    with pytest.raises(TypeError):
        model.set(f"{PROT}/PTRC1.Tr.q[ST]", OctetStringData(b"x"))


def test_a_batch_notifies_once_at_its_end(model: IedModel) -> None:
    seen = []
    model.add_listener(lambda nodes: seen.append([n.item for n in nodes]))
    with model.batch():
        model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)
        with model.batch():  # nested: ends with the outer one
            model.set("IED01MU/IMMXU1.A.phsA.cVal.mag.f[MX]", 12.5)
        assert seen == []
    assert seen == [["PTRC1$ST$Tr$general", "IMMXU1$MX$A$phsA$cVal$mag$f"]]
    with pytest.raises(KeyError), model.batch():  # what was changed before the error still goes out
        model.set(f"{PROT}/PTRC1.Tr.general[ST]", False)
        model.set(f"{PROT}/LLN0$ST$Nope", 1)
    assert seen[-1] == ["PTRC1$ST$Tr$general"]


def test_association_names_and_model(server: MmsServer) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        association = client.association
        assert association is not None and association.max_pdu_size == 65000 and association.supports(4)
        assert client.get_name_list(OBJECT_CLASS_DOMAIN) == ["IED01MU", PROT]
        assert client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE_LIST, PROT) == ["LLN0$DS_TRIP"]
        assert compare(scl.load_model(SCD), discover(client, types=True)) == []
        with pytest.raises(ServiceError):
            client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, "NO_SUCH_LD")


def test_name_list_pages(model: IedModel) -> None:
    with MmsServer(model, "127.0.0.1", 0, max_pdu_size=300) as server:
        server.start()
        with MmsClient.connect("127.0.0.1", server.port) as client:
            names = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, PROT)  # several pages, continueAfter
    assert names == model.names(PROT) and len(names) > 40


def test_read_write_rules(server: MmsServer, model: IedModel) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)
        results = client.read_many([f"{PROT}/PTRC1.Tr.general[ST]", f"{PROT}/PTRC1$ST$Nope", f"{PROT}/LLN0.Mod.stVal[ST]"])
        assert results[0] == BoolData(True) and isinstance(results[1], DataAccessError) and results[1].code == 10
        errors = client.write_many([f"{PROT}/LLN0$CF$Mod$ctlModel", f"{PROT}/LLN0$ST$Mod$stVal", f"{PROT}/LLN0$CF$Mod$ctlModel"],
                                   [IntData(4), IntData(1), BoolData(True)])
        assert errors[0] is None
        assert [e.code for e in errors[1:]] == [3, 7]  # access denied (ST), type inconsistent
        assert client.read(f"{PROT}/LLN0.Mod.ctlModel[CF]") == IntData(4)
        assert client.get_data_set_members(f"{PROT}/LLN0.DS_TRIP")[1] == ObjectName("IMMXU1$MX$A$phsA", "IED01MU")
        mod = client.get_type(f"{PROT}/LLN0$ST$Mod")
        assert mod == StructureType([("stVal", PrimitiveType("integer", 8)), ("q", PrimitiveType("bit-string", -13))])
        with pytest.raises(ServiceError):
            client.get_type(f"{PROT}/LLN0$ST$Nope")


def test_raw_services(server: MmsServer, model: IedModel) -> None:
    """Read of a data set by its list name, Identify, an unknown service, Conclude."""
    with MmsClient.connect("127.0.0.1", server.port) as client:
        list_name = ber.encode_tlv(0xA1, pdu.encode_object_name(ObjectName("LLN0$DS_TRIP", PROT)))
        read = ber.encode_tlv(0xA4, ber.encode_tlv(0x80, b"\xff") + ber.encode_tlv(0xA1, list_name))
        response = client.request(read)
        assert response.service == pdu.SERVICE_READ
        assert len(pdu.read_response(response.content)) == 2
        identify = client.request(ber.encode_tlv(0x82))
        fields = {t.tag: t.value for t in ber.iter_tlvs(identify.content)}
        assert fields[0x80] == b"open61850" and fields[0x82].decode() == __import__("open61850").__version__
        with pytest.raises(MmsReject):
            client.request(ber.encode_tlv(0xBF48, b""))  # fileOpen: not served
        assert client.read(f"{PROT}/LLN0.Mod.stVal[ST]") == IntData(0)  # still usable after a reject


def test_server_stop_closes_clients(model: IedModel) -> None:
    server = MmsServer(model, "127.0.0.1", 0)
    server.start()
    client = MmsClient.connect("127.0.0.1", server.port)
    assert len(server.connections) == 1
    server.stop()
    assert client.wait_closed(5) is not None or not client.is_connected
    client.close()


# --- reports -----------------------------------------------------------------------

import gc  # noqa: E402
import queue  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

from open61850.mms import decode_report, rcb  # noqa: E402

BRCBS = [ObjectName(f"LLN0$BR$brcbTrip0{i}", PROT) for i in (1, 2)]
TRIP = f"{PROT}/PTRC1.Tr.general[ST]"


def _reports(q: queue.Queue, wait: float = 0.3) -> list:
    time.sleep(wait)
    out = []
    while not q.empty():
        out.append(decode_report(q.get()))
    return out


def _reasons(report) -> list[list[str]]:
    return [[k for k, v in vars(e.reason).items() if v] for e in report.entries]


def test_brcb_gi_change_integrity_and_release(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        free = rcb.find_free(client, BRCBS)
        assert free.rcb == BRCBS[0]
        # IntgPd well beyond the GI and change windows below, which a slow CI runner stretches.
        rcb.enable(client, free.rcb, rcb.RcbSettings(intg_pd_ms=600, purge_buf=True))
        (gi,) = _reports(q, 0.1)
        assert gi.rpt_id == f"{PROT}/LLN0$BR$brcbTrip01" and _reasons(gi) == [["general_interrogation"]] * 2
        model.set(TRIP, True)
        model.set(f"{PROT}/PTRC1.Tr.q[ST]", 0x0800)  # q is not in the data set: nothing
        (change,) = _reports(q, 0.1)
        assert [(e.index, e.value) for e in change.entries] == [(0, BoolData(True))] and _reasons(change) == [["data_change"]]
        integrity = _reports(q, 0.65)
        assert integrity and _reasons(integrity[0]) == [["integrity"]] * 2
        seq = [gi.seq_num, change.seq_num, integrity[0].seq_num]
        assert seq == [0, 1, 2] and int.from_bytes(change.entry_id, "big") == int.from_bytes(gi.entry_id, "big") + 1
        with MmsClient.connect("127.0.0.1", server.port) as other:
            with pytest.raises(rcb.RcbError):  # reserved by the first client
                rcb.enable(other, free.rcb)
            assert rcb.find_free(other, BRCBS).rcb == BRCBS[1]
            with pytest.raises(DataAccessError):  # configuration is frozen while enabled
                client.write(f"{PROT}/LLN0$BR$brcbTrip01$IntgPd", __import__("open61850").data.UIntData(1000))
        rcb.disable(client, free.rcb)
    status = model.get(f"{PROT}/LLN0$BR$brcbTrip01$RptEna")
    assert status == BoolData(False)


def test_buftm_gathers_changes(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, buf_tm_ms=150, general_interrogation=False))
        model.set(TRIP, True)
        model.set("IED01MU/IMMXU1.A.phsA.q[MX]", 0x0800)  # no qchg on this q in the SCL: not reported
        model.set(TRIP, False)  # the same member again: the first entry goes at once
        reports = _reports(q, 0.3)
        assert [[(e.index, e.value) for e in r.entries] for r in reports] == [[(0, BoolData(True))], [(0, BoolData(False))]]


def test_a_batch_makes_one_report(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, general_interrogation=False))
        with model.batch():  # without, three reports
            model.set(TRIP, True)
            model.set(TRIP, False)
            model.set(TRIP, True)
        (report,) = _reports(q, 0.2)
        assert [(e.index, e.value) for e in report.entries] == [(0, BoolData(True))]


def test_buffered_entries_replayed_from_entry_id(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, purge_buf=True, resv_tms=2))
        (gi,) = _reports(q, 0.1)
    # the client is gone; the block keeps buffering and stays reserved for its address
    model.set(TRIP, True)
    model.set(TRIP, False)
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        settings = rcb.RcbSettings(intg_pd_ms=0, entry_id=gi.entry_id, general_interrogation=False)
        rcb.enable(client, BRCBS[0], settings)  # same address: its reservation
        replay = _reports(q, 0.2)
        assert [r.entries[0].value for r in replay] == [BoolData(True), BoolData(False)]
        rcb.disable(client, BRCBS[0])
        client.write(f"{PROT}/LLN0$BR$brcbTrip01$PurgeBuf", BoolData(True))
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, entry_id=bytes(8), general_interrogation=False))
        assert _reports(q, 0.2) == []  # purged


def test_buffer_overflow_only_when_unsent_entries_are_dropped(model: IedModel, monkeypatch: pytest.MonkeyPatch) -> None:
    from open61850.server import reporting

    monkeypatch.setattr(reporting, "BUFFER_ENTRIES", 5)
    q: queue.Queue = queue.Queue()
    with MmsServer(model, "127.0.0.1", 0) as server:
        server.start()
        with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
            settings = rcb.RcbSettings(intg_pd_ms=0, purge_buf=True, resv_tms=2, general_interrogation=False)
            rcb.enable(client, BRCBS[0], settings)
            for i in range(8):  # beyond the buffer, each entry sent as it is made: nothing is lost
                model.set(TRIP, i % 2 == 0)
            live = _reports(q, 0.2)
            assert [r.buf_ovfl for r in live] == [False] * 8
        deadline = time.monotonic() + 3
        while model.get(f"{PROT}/LLN0$BR$brcbTrip01$RptEna") == BoolData(True) and time.monotonic() < deadline:
            time.sleep(0.02)
        for i in range(8):  # the client is gone: the buffer drops three entries it never sent
            model.set(TRIP, i % 2 == 0)
        with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
            settings = rcb.RcbSettings(intg_pd_ms=0, entry_id=live[-1].entry_id, general_interrogation=False)
            rcb.enable(client, BRCBS[0], settings)
            assert [r.buf_ovfl for r in _reports(q, 0.2)] == [True] + [False] * 4
            model.set(TRIP, True)
            assert [r.buf_ovfl for r in _reports(q, 0.2)] == [False]


def test_buffer_bounded_in_bytes(model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsServer(model, "127.0.0.1", 0, report_buffer_bytes=1) as server:  # room for the newest entry alone
        server.start()
        with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
            settings = rcb.RcbSettings(intg_pd_ms=0, purge_buf=True, resv_tms=2, general_interrogation=False)
            rcb.enable(client, BRCBS[0], settings)
            model.set(TRIP, True)
            (live,) = _reports(q, 0.2)
        deadline = time.monotonic() + 3
        while model.get(f"{PROT}/LLN0$BR$brcbTrip01$RptEna") == BoolData(True) and time.monotonic() < deadline:
            time.sleep(0.02)
        for i in range(4):
            model.set(TRIP, i % 2 == 1)
        with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
            settings = rcb.RcbSettings(intg_pd_ms=0, entry_id=live.entry_id, general_interrogation=False)
            rcb.enable(client, BRCBS[0], settings)
            (replay,) = _reports(q, 0.2)
            assert replay.buf_ovfl and replay.entries[0].value == BoolData(True)  # the last change, three dropped


def test_a_buffered_entry_is_one_object_for_the_collector(server: MmsServer, model: IedModel) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, purge_buf=True))
        for _ in range(20):  # general interrogations: every member, the measurement's structure among them
            client.write(f"{PROT}/LLN0$BR$brcbTrip01$GI", BoolData(True))
        model.set(TRIP, True)
        assert server.reports is not None
        buffer = list(server.reports.controls[(PROT, "LLN0$BR$brcbTrip01")].buffer)
    assert len(buffer) == 22
    gc.collect()  # tuples of numbers leave the collector's lists on its first pass
    assert [x for entry in buffer for x in gc.get_referents(entry) if gc.is_tracked(x) and not isinstance(x, type)] == []


def test_a_kept_reservation_ends(server: MmsServer, model: IedModel) -> None:
    resv_tms = f"{PROT}/LLN0$BR$brcbTrip01$ResvTms"
    with MmsClient.connect("127.0.0.1", server.port) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, resv_tms=1, general_interrogation=False))
    deadline = time.monotonic() + 3
    while model.get(f"{PROT}/LLN0$BR$brcbTrip01$RptEna") == BoolData(True) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert model.get(resv_tms) == IntData(1)  # kept for the client that left
    with MmsClient.connect("127.0.0.1", server.port) as other:
        assert not rcb.read_status(other, BRCBS[0]).free
        deadline = time.monotonic() + 3
        while model.get(resv_tms) != IntData(0) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert model.get(resv_tms) == IntData(0)
        assert rcb.find_free(other, BRCBS).rcb == BRCBS[0]  # free again for any client


def test_disconnect_disables_the_block(server: MmsServer, model: IedModel) -> None:
    client = MmsClient.connect("127.0.0.1", server.port)
    rcb.enable(client, BRCBS[1], rcb.RcbSettings(intg_pd_ms=0, resv_tms=0, general_interrogation=False))
    assert model.get(f"{PROT}/LLN0$BR$brcbTrip02$RptEna") == BoolData(True)
    client.close()
    deadline = time.monotonic() + 2
    while model.get(f"{PROT}/LLN0$BR$brcbTrip02$RptEna") == BoolData(True) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert model.get(f"{PROT}/LLN0$BR$brcbTrip02$RptEna") == BoolData(False)
    with MmsClient.connect("127.0.0.1", server.port) as other:
        assert rcb.find_free(other, [BRCBS[1]]) is not None  # ResvTms 0: released at once


# --- command line --------------------------------------------------------------------


def test_server_command_line() -> None:
    import os
    import re
    import subprocess
    import sys

    from conftest import ROOT

    process = subprocess.Popen(
        [sys.executable, "-m", "open61850.server", str(SCD), "--host", "127.0.0.1", "--port", "0", "--duration", "10"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    try:
        banner = process.stderr.readline()
        port = int(re.search(r":(\d+)$", banner.strip()).group(1))
        assert banner.startswith("open61850-server: IED01 (IED01_Protection, IED01MU) on 127.0.0.1:")
        process.stdin.write(f"{TRIP} true\nIED01MU/IMMXU1.A.phsA.cVal.mag.f[MX] 42.5\n{PROT}/NOPE[ST] 1\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == f"{TRIP} = bool(True)"
        assert process.stdout.readline().strip().endswith("= float32(42.5)")
        assert "no " in process.stderr.readline()
        with MmsClient.connect("127.0.0.1", port) as client:
            assert client.read(TRIP) == BoolData(True)
    finally:
        process.terminate()
        process.wait(10)


# --- controls --------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

from open61850.data import BitStringData  # noqa: E402
from open61850.mms import ControlError, operate  # noqa: E402
from open61850.mms.control import oper_value  # noqa: E402

CTRL = "IED01CTRL"
ON, OFF = BitStringData(b"\x80", 6), BitStringData(b"\x40", 6)  # Dbpos on (10), off (01)


@pytest.fixture
def switches() -> Iterator[MmsServer]:
    with MmsServer(IedModel.from_scl(DATA_DIR / "controls.scd.xml"), "127.0.0.1", 0) as srv:
        srv.start()
        yield srv


@pytest.mark.parametrize("ln, model, terminated", [
    ("CSWI1", "direct-with-normal-security", False),
    ("CSWI2", "sbo-with-normal-security", False),
    ("CSWI3", "direct-with-enhanced-security", True),
    ("CSWI4", "sbo-with-enhanced-security", True),
])
def test_control_models(switches: MmsServer, ln: str, model: str, terminated: bool) -> None:
    with MmsClient.connect("127.0.0.1", switches.port) as client:
        result = operate(client, f"{CTRL}/{ln}.Pos", True, ctl_num=7)
        assert str(result).startswith(model) and result.terminated is terminated
        assert client.read(f"{CTRL}/{ln}.Pos.stVal[ST]") == ON
        assert client.read(f"{CTRL}/{ln}.Pos.ctlNum[ST]") == UIntData(7)
        operate(client, f"{CTRL}/{ln}.Pos", False)
        assert client.read(f"{CTRL}/{ln}.Pos.stVal[ST]") == OFF


def test_control_refusals(switches: MmsServer) -> None:
    switches.controls.set_handler(f"{CTRL}/CSWI3.Pos", lambda command: 10)  # blocked-by-interlocking
    switches.controls.set_handler(f"{CTRL}/CSWI1.Pos", lambda command: 10)
    with MmsClient.connect("127.0.0.1", switches.port) as client, \
            MmsClient.connect("127.0.0.1", switches.port) as other:
        with pytest.raises(ControlError) as refused:
            operate(client, f"{CTRL}/CSWI3.Pos", True)
        assert refused.value.stage == "termination" and refused.value.last_appl_error.add_cause == 10
        with pytest.raises(ControlError) as refused:
            operate(client, f"{CTRL}/CSWI1.Pos", True)  # normal security: LastApplError, then the refusal
        assert refused.value.stage == "operate" and refused.value.last_appl_error.add_cause == 10
        with pytest.raises(ControlError, match="ctlModel 0"):
            operate(client, f"{CTRL}/CSWI5.Pos", True)
        with pytest.raises(DataAccessError):  # Oper of an SBO object without selection
            client.write(f"{CTRL}/CSWI2$CO$Pos$Oper", oper_value(True))
        # a selection belongs to its client, and lapses after sboTimeout (300 ms here)
        assert client.read(f"{CTRL}/CSWI2$CO$Pos$SBO") == VisibleStringData(f"{CTRL}/CSWI2$CO$Pos")
        assert other.read(f"{CTRL}/CSWI2$CO$Pos$SBO") == VisibleStringData("")
        time.sleep(0.35)
        assert other.read(f"{CTRL}/CSWI2$CO$Pos$SBO") == VisibleStringData(f"{CTRL}/CSWI2$CO$Pos")
        client.write(f"{CTRL}/CSWI4$CO$Pos$SBOw", oper_value(True))
        with pytest.raises(ControlError) as refused:
            operate(other, f"{CTRL}/CSWI4.Pos", True)
        assert refused.value.last_appl_error.add_cause == 19  # object-already-selected
        cancel = StructureData(oper_value(True).members[:5])
        client.write(f"{CTRL}/CSWI4$CO$Pos$Cancel", cancel)
        operate(other, f"{CTRL}/CSWI4.Pos", True)
        with pytest.raises(DataAccessError):  # ST is not written by clients, CO only through the services
            client.write(f"{CTRL}/CSWI1$CO$Pos$Oper$ctlVal", BoolData(True))


def test_control_test_flag_and_time_activation(switches: MmsServer) -> None:
    commands = []
    switches.controls.set_handler(f"{CTRL}/CSWI1.Pos", lambda command: commands.append(command))
    with MmsClient.connect("127.0.0.1", switches.port) as client:
        operate(client, f"{CTRL}/CSWI1.Pos", True, test=True)
        assert commands == []  # checked, not executed
        operate(client, f"{CTRL}/CSWI1.Pos", True, ctl_num=3, interlock_check=False)
        (command,) = commands
        assert (command.reference, command.ctl_val, command.ctl_num) == (f"{CTRL}/CSWI1$CO$Pos", BoolData(True), 3)
        assert command.synchro_check and not command.interlock_check and not command.test


def test_control_checks_refuse_before_the_response(switches: MmsServer) -> None:
    executed = []
    for ln in ("CSWI3", "CSWI4"):
        switches.controls.set_check(f"{CTRL}/{ln}.Pos", lambda command: 10)  # blocked-by-interlocking
        switches.controls.set_handler(f"{CTRL}/{ln}.Pos", executed.append)
    with MmsClient.connect("127.0.0.1", switches.port) as client:
        with pytest.raises(ControlError) as refused:  # enhanced security: refused at Oper, not by the termination
            operate(client, f"{CTRL}/CSWI3.Pos", True)
        assert refused.value.stage == "operate" and refused.value.last_appl_error.add_cause == 10
        with pytest.raises(ControlError) as refused:  # SBOw is checked too
            operate(client, f"{CTRL}/CSWI4.Pos", True)
        assert refused.value.stage == "select" and refused.value.last_appl_error.add_cause == 10
    assert executed == []


def test_control_in_execution_until_finished(switches: MmsServer) -> None:
    from open61850.server.control import ADD_CAUSE_TIME_LIMIT_OVER, IN_EXECUTION

    for ln in ("CSWI1", "CSWI3"):
        switches.controls.set_handler(f"{CTRL}/{ln}.Pos", lambda command: IN_EXECUTION)
    with MmsClient.connect("127.0.0.1", switches.port) as client, \
            MmsClient.connect("127.0.0.1", switches.port) as other:
        operate(client, f"{CTRL}/CSWI1.Pos", True)  # normal security: done for the client at once
        assert switches.controls.executing(f"{CTRL}/CSWI1.Pos")
        with pytest.raises(ControlError) as refused:
            operate(other, f"{CTRL}/CSWI1.Pos", False)
        assert refused.value.last_appl_error.add_cause == 12  # command-already-in-execution
        assert switches.controls.finish(f"{CTRL}/CSWI1.Pos") and not switches.controls.finish(f"{CTRL}/CSWI1.Pos")
        operate(other, f"{CTRL}/CSWI1.Pos", False)

        def finish_later(cause: object) -> None:
            def run() -> None:
                while not switches.controls.executing(f"{CTRL}/CSWI3.Pos"):
                    time.sleep(0.01)
                time.sleep(0.2)
                switches.controls.finish(f"{CTRL}/CSWI3.Pos", cause)  # type: ignore[arg-type]
            threading.Thread(target=run, daemon=True).start()

        finish_later(None)
        start = time.monotonic()
        result = operate(client, f"{CTRL}/CSWI3.Pos", True)  # enhanced: the termination waits for finish
        assert result.terminated and time.monotonic() - start >= 0.2
        finish_later(ADD_CAUSE_TIME_LIMIT_OVER)
        with pytest.raises(ControlError) as refused:
            operate(client, f"{CTRL}/CSWI3.Pos", False)
        assert refused.value.stage == "termination" and refused.value.last_appl_error.add_cause == 16
        assert not switches.controls.executing(f"{CTRL}/CSWI3.Pos")


def test_control_shows_the_operation_received_and_given(switches: MmsServer) -> None:
    """7-3 edition 2.1's opRcvd and opOk (FC OR): received, given with tOpOk, both down at the end of the command;
    a test command received only."""
    from open61850.server.control import IN_EXECUTION

    seen: list[tuple[str, bool]] = []
    switches.model.add_listener(lambda nodes: seen.extend(
        (f"{n.parent.parent.parent.name}.{n.name}", n.data().value) for n in nodes if n.name in ("opRcvd", "opOk")))
    switches.controls.set_handler(f"{CTRL}/CSWI3.Pos", lambda command: IN_EXECUTION)
    with MmsClient.connect("127.0.0.1", switches.port) as client:
        operate(client, f"{CTRL}/CSWI1.Pos", True)
        assert seen == [("CSWI1.opRcvd", True), ("CSWI1.opOk", True), ("CSWI1.opOk", False), ("CSWI1.opRcvd", False)]
        assert client.read(f"{CTRL}/CSWI1.Pos.tOpOk[OR]") != TimestampData(datetime.fromtimestamp(0, timezone.utc))
        seen.clear()
        operate(client, f"{CTRL}/CSWI1.Pos", False, test=True)
        assert seen == [("CSWI1.opRcvd", True), ("CSWI1.opRcvd", False)]
        seen.clear()
        threading.Thread(target=lambda: operate(client, f"{CTRL}/CSWI3.Pos", True), daemon=True).start()
        while not switches.controls.executing(f"{CTRL}/CSWI3.Pos"):
            time.sleep(0.01)
        assert seen == [("CSWI3.opRcvd", True), ("CSWI3.opOk", True)]
        switches.controls.finish(f"{CTRL}/CSWI3.Pos")
        assert seen[2:] == [("CSWI3.opOk", False), ("CSWI3.opRcvd", False)]


def test_time_activated_operate_waits_for_oper_tm(tmp_path) -> None:
    scd = (DATA_DIR / "controls.scd.xml").read_text().replace(
        '<BDA name="ctlVal" bType="BOOLEAN"/>\n      <BDA name="origin"',
        '<BDA name="ctlVal" bType="BOOLEAN"/>\n      <BDA name="operTm" bType="Timestamp"/>\n      <BDA name="origin"', 1)
    path = tmp_path / "timed.scd.xml"
    path.write_text(scd)
    with MmsServer(IedModel.from_scl(path), "127.0.0.1", 0) as server:
        server.start()
        with MmsClient.connect("127.0.0.1", server.port) as client:
            for ln in ("CSWI1", "CSWI3"):
                start = time.monotonic()
                result = operate(client, f"{CTRL}/{ln}.Pos", True, oper_tm=datetime.now(timezone.utc) + timedelta(seconds=0.25))
                if result.terminated:  # enhanced: the termination follows the execution
                    assert time.monotonic() - start >= 0.2
                    assert client.read(f"{CTRL}/{ln}.Pos.stVal[ST]") == ON
                else:
                    assert client.read(f"{CTRL}/{ln}.Pos.stVal[ST]") == OFF
                    time.sleep(0.35)
                    assert client.read(f"{CTRL}/{ln}.Pos.stVal[ST]") == ON


def test_a_data_set_written_on_a_block_is_the_one_reported(server: MmsServer, model: IedModel) -> None:
    """The members a change reaches are looked up by name, made once: a DatSet a client writes makes them again."""
    q: queue.Queue = queue.Queue()
    dat_set = f"{PROT}/LLN0$BR$brcbTrip01$DatSet"
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, general_interrogation=False))
        model.set(TRIP, True)
        assert len(_reports(q, 0.2)) == 1
        rcb.disable(client, BRCBS[0])
        client.write(dat_set, VisibleStringData(""))  # no data set: nothing to report
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, general_interrogation=False))
        model.set(TRIP, False)
        assert _reports(q, 0.2) == []
        rcb.disable(client, BRCBS[0])
        client.write(dat_set, VisibleStringData(f"{PROT}/LLN0$DS_TRIP"))
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, general_interrogation=False))
        model.set(TRIP, True)
        (report,) = _reports(q, 0.2)
        assert [(e.index, e.value) for e in report.entries] == [(0, BoolData(True))]


def test_a_change_does_not_go_through_every_block(server: MmsServer, model: IedModel,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    """A change is looked up in the data sets' members by name: the blocks' data sets are read once, whatever the
    number of changes. Read again for each change and each block, as before, a relay of 14 bays fed measurements
    that move at each computation (a network computed in time) held the model until no read was answered."""
    from open61850.server import reporting

    reads, added = [], []
    members = reporting.ReportControl.members
    monkeypatch.setattr(reporting.ReportControl, "members", lambda self: reads.append(self) or members(self))
    with MmsClient.connect("127.0.0.1", server.port) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, general_interrogation=False))
        monkeypatch.setattr(server.reports, "_add", lambda block, reasons: added.append((block, reasons)))
        reads.clear()
        for i in range(20):
            model.set(TRIP, i % 2 == 0)
            model.set("IED01MU/IMMXU1.A.phsA.q[MX]", i)  # in no data set
        assert [(block.node.name, list(reasons)) for block, reasons in added] == [("brcbTrip01", [0])] * 20
        assert len(reads) <= len(server.reports.controls)  # the index, made once


def test_a_client_that_stops_reading_is_dropped_without_stopping_the_server(model: IedModel) -> None:
    # The report callback never returns, so the client stops reading: its socket fills up.
    stuck = threading.Event()
    with MmsServer(model, "127.0.0.1", 0, send_timeout=0.5) as server:
        server.start()
        client = MmsClient.connect("127.0.0.1", server.port, on_information_report=lambda _: stuck.wait())
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, resv_tms=0, general_interrogation=False))
        (connection,) = server.connections
        connection.iso._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        client._conn._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        done = threading.Event()

        def changes() -> None:
            for i in range(20000):
                model.set(TRIP, i % 2 == 0)
            done.set()

        threading.Thread(target=changes, daemon=True).start()
        assert done.wait(10), "model changes blocked behind a client that does not read"
        deadline = time.monotonic() + 5
        while server.connections and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not server.connections and connection.closed.is_set()
        with MmsClient.connect("127.0.0.1", server.port) as other:
            assert other.read(TRIP) in (BoolData(True), BoolData(False))
        stuck.set()
        client.close()


def test_a_client_too_far_behind_is_dropped(model: IedModel) -> None:
    stuck = threading.Event()
    with MmsServer(model, "127.0.0.1", 0, send_queue_bytes=64 * 1024) as server:
        server.start()
        client = MmsClient.connect("127.0.0.1", server.port, on_information_report=lambda _: stuck.wait())
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, resv_tms=0, general_interrogation=False))
        (connection,) = server.connections
        connection.iso._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        client._conn._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        for i in range(20000):
            model.set(TRIP, i % 2 == 0)
            if connection.closed.is_set():
                break
        assert connection.closed.is_set()
        stuck.set()
        client.close()


def test_accepted_sockets_notice_a_vanished_peer(server: MmsServer) -> None:
    with MmsClient.connect("127.0.0.1", server.port):
        (connection,) = server.connections
        sock = connection.iso._sock
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
        if hasattr(socket, "TCP_USER_TIMEOUT"):
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == int(server.keepalive * 1000)
